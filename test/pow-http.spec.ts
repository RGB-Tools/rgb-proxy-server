import crypto from "crypto";
import fs from "fs";
import path from "path";
import request from "supertest";

import app from "../src/app";
import {
  deriveTransferId,
  hashUtf8Message,
  loadApiEndpoints,
} from "../src/controllers/api";
import { leadingZeroBits, powDigest } from "../src/pow";

const jsonrpcVersion = "2.0";
const okStatus = 200;

// ---------------------------------------------------------------------------
// Helpers
//
// Mirror api.spec.ts, duplicated to keep this file's proof of work setup
// fully independent of the shared suite.
// ---------------------------------------------------------------------------

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

interface Keypair {
  privateKey: crypto.KeyObject;
  pubkeyHex: string;
}

function generateKeypair(): Keypair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pubkeyHex = spkiDer.slice(SPKI_PREFIX.length).toString("hex");
  return { privateKey, pubkeyHex };
}

function sign(privateKey: crypto.KeyObject, message: Buffer): string {
  return crypto.sign(null, message, privateKey).toString("hex");
}

function sha256hex(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function randomId(): string {
  return crypto.randomBytes(32).toString("hex");
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

async function rpc(method: string, params: object) {
  return request(app)
    .post("/json-rpc")
    .send({ jsonrpc: jsonrpcVersion, id: "1", method, params })
    .expect(okStatus);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const tempDir = fs.mkdtempSync(path.join(__dirname, "temp-pow-"));
process.env.APP_DATA = path.join(tempDir, "app-data");

// Small difficulties, so that proofs of work are cheap to compute. The decayed
// call count is slightly lower than the number of calls, as some time passes
// between them: with a threshold of 2 and a step of 1 the per-invoice
// difficulty is 1 after the 3rd call and 2 after the 4th one. The global
// difficulty is 1 after the 10th call across all invoices.
const maxPowDifficulty = 6;
process.env.MAX_POW_DIFFICULTY = String(maxPowDifficulty);
process.env.POW_RATE_THRESHOLD = "2";
process.env.POW_RATE_STEP = "1";
process.env.POW_GLOBAL_THRESHOLD = "9";
process.env.POW_GLOBAL_STEP = "1";
process.env.MAX_QUOTA = "10";

loadApiEndpoints(app);

afterAll(() => {
  return fs.promises.rm(tempDir, { recursive: true, force: true });
});

interface Transfer {
  invoiceId: string;
  transferId: string;
  sender: Keypair;
}

async function prepareInvoice(quota: string) {
  const recipient = generateKeypair();
  const invoiceId = randomId();
  const res = await rpc("invoice.prepare", {
    invoice_id: invoiceId,
    expires_at: String(nowSecs() + 3600),
    recipient_pk: recipient.pubkeyHex,
    quota,
  });
  expect(res.body.result).toBe(true);
  return { invoiceId, recipient };
}

function newTransfer(invoiceId: string): Transfer {
  const sender = generateKeypair();
  return {
    invoiceId,
    transferId: deriveTransferId(invoiceId, sender.pubkeyHex),
    sender,
  };
}

// First nonce whose puzzle hash has at least (or, if !valid, less than) the
// given number of leading zero bits
function findNonce(
  transferId: string,
  powTimestamp: string,
  difficulty: number,
  valid = true,
): string {
  for (let nonce = 0; ; nonce++) {
    const bits = leadingZeroBits(
      powDigest(transferId, powTimestamp, String(nonce)),
    );
    if (bits >= difficulty === valid) return String(nonce);
  }
}

async function postConsignment(
  t: Transfer,
  content: string,
  powTimestamp: string,
  powNonce: string,
) {
  const consignmentHash = sha256hex("plaintext " + content);
  return request(app)
    .post("/json-rpc")
    .set("Content-type", "multipart/form-data")
    .field("jsonrpc", jsonrpcVersion)
    .field("id", "1")
    .field("method", "consignment.post")
    .field(
      "params",
      JSON.stringify({
        invoice_id: t.invoiceId,
        transfer_id: t.transferId,
        sender_transport_endpoint: "rpc://sender.example.com/json-rpc",
        sender_pk: t.sender.pubkeyHex,
        consignment_hash: consignmentHash,
        batch: false,
        file_size: String(Buffer.byteLength(content)),
        signature: sign(
          t.sender.privateKey,
          hashUtf8Message(t.transferId + consignmentHash + sha256hex(content)),
        ),
        pow_timestamp: powTimestamp,
        pow_nonce: powNonce,
      }),
    )
    .attach("file", Buffer.from(content), "consignment")
    .expect(okStatus);
}

// Posts with a valid proof of work for the given difficulty
async function postWithPow(t: Transfer, content: string, difficulty: number) {
  const powTimestamp = String(nowSecs());
  return postConsignment(
    t,
    content,
    powTimestamp,
    findNonce(t.transferId, powTimestamp, difficulty),
  );
}

async function difficultyOf(invoiceId: string): Promise<number> {
  const res = await rpc("invoice.check", { invoice_ids: [invoiceId] });
  return parseInt(res.body.result[invoiceId].pow_difficulty);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("adaptive proof of work over HTTP", () => {
  // the tests share the proxy-wide call count, so they run in order

  it("server.info exposes the max difficulty", async () => {
    const res = await rpc("server.info", {});
    expect(res.body.result.max_pow_difficulty).toBe(String(maxPowDifficulty));
  });

  let invoice: { invoiceId: string; recipient: Keypair };
  const transfers: Transfer[] = [];

  it("rises with the calls for an invoice and is verified", async () => {
    invoice = await prepareInvoice("4");
    for (let i = 0; i < 4; i++) transfers.push(newTransfer(invoice.invoiceId));
    const [t1, t2, t3, t4] = transfers;

    // difficulty 0: any proof of work is accepted, also a stale one
    expect(await difficultyOf(invoice.invoiceId)).toBe(0);
    let res = await postConsignment(t1, "pow 1", "1", "any");
    expect(res.body.result).toBe(true);
    res = await postConsignment(t2, "pow 2", "1", "any");
    expect(res.body.result).toBe(true);
    expect(await difficultyOf(invoice.invoiceId)).toBe(0);
    res = await postConsignment(t3, "pow 3", String(nowSecs()), "0");
    expect(res.body.result).toBe(true);
    expect(await difficultyOf(invoice.invoiceId)).toBe(1);

    // checking the difficulty does not count as a call
    for (let i = 0; i < 10; i++) await difficultyOf(invoice.invoiceId);
    expect(await difficultyOf(invoice.invoiceId)).toBe(1);

    // insufficient proof of work: the current difficulty is reported
    const powTimestamp = String(nowSecs());
    res = await postConsignment(
      t4,
      "pow 4",
      powTimestamp,
      findNonce(t4.transferId, powTimestamp, 1, false),
    );
    expect(res.body.error.code).toBe(-114);
    expect(res.body.error.message).toBe("Invalid proof of work");
    expect(res.body.error.data).toEqual({ pow_difficulty: "1" });

    // valid proof of work, but out of the allowed time window
    for (const offset of [-301, 301]) {
      const staleTimestamp = String(nowSecs() + offset);
      res = await postConsignment(
        t4,
        "pow 4",
        staleTimestamp,
        findNonce(t4.transferId, staleTimestamp, 6),
      );
      expect(res.body.error.code).toBe(-114);
    }

    // malformed proof of work fields are invalid
    res = await postConsignment(t4, "pow 4", "-1", "0");
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["pow_timestamp"]);

    // retry with the reported difficulty
    res = await postWithPow(t4, "pow 4", 1);
    expect(res.body.result).toBe(true);
    expect(await difficultyOf(invoice.invoiceId)).toBe(2);
  });

  it("is not required for identical re-posts", async () => {
    const res = await postConsignment(transfers[0], "pow 1", "1", "any");
    expect(res.body.result).toBe(false);
  });

  it("is checked after the other checks", async () => {
    // quota exceeded
    const t5 = newTransfer(invoice.invoiceId);
    let res = await postConsignment(t5, "pow 5", "1", "any");
    expect(res.body.error.code).toBe(-112);

    // transfer ID deleted
    const deleted = transfers[0];
    res = await rpc("transfer.delete", {
      transfer_id: deleted.transferId,
      signature: sign(
        invoice.recipient.privateKey,
        hashUtf8Message(deleted.transferId + "delete"),
      ),
    });
    expect(res.body.result).toBe(true);
    res = await postConsignment(deleted, "pow 1", "1", "any");
    expect(res.body.error.code).toBe(-113);

    // the slot freed by the deletion still requires the proof of work
    res = await postConsignment(t5, "pow 5", "1", "any");
    expect(res.body.error.code).toBe(-114);
    expect(res.body.error.data).toEqual({ pow_difficulty: "2" });
    res = await postWithPow(t5, "pow 5", 2);
    expect(res.body.result).toBe(true);
    expect(await difficultyOf(invoice.invoiceId)).toBe(3);
  });

  it("rises for all invoices with the calls across the proxy", async () => {
    // 5 calls so far: 5 more across invoices staying below the per-invoice
    // threshold
    for (let i = 0; i < 2; i++) {
      const other = await prepareInvoice("2");
      for (let j = 0; j < 2; j++) {
        const res = await postConsignment(
          newTransfer(other.invoiceId),
          `global ${i} ${j}`,
          "1",
          "any",
        );
        expect(res.body.result).toBe(true);
      }
    }
    const lastInvoice = await prepareInvoice("2");
    expect(await difficultyOf(lastInvoice.invoiceId)).toBe(0);
    let res = await postConsignment(
      newTransfer(lastInvoice.invoiceId),
      "global last",
      "1",
      "any",
    );
    expect(res.body.result).toBe(true);

    // 10 calls: the global difficulty applies to every invoice, even unknown
    // ones
    expect(await difficultyOf(lastInvoice.invoiceId)).toBe(1);
    const unknownId = randomId();
    res = await rpc("invoice.check", { invoice_ids: [unknownId] });
    expect(res.body.result[unknownId]).toEqual({
      status: "unknown",
      pow_difficulty: "1",
    });
    // the per-invoice difficulty is higher than the global one
    expect(await difficultyOf(invoice.invoiceId)).toBe(3);

    const t = newTransfer(lastInvoice.invoiceId);
    res = await postConsignment(t, "global pow", "1", "any");
    expect(res.body.error.code).toBe(-114);
    expect(res.body.error.data).toEqual({ pow_difficulty: "1" });
    res = await postWithPow(t, "global pow", 1);
    expect(res.body.result).toBe(true);
  });
});
