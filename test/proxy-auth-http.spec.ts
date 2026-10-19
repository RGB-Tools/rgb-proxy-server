import crypto from "crypto";
import express from "express";
import fs from "fs";
import path from "path";
import request from "supertest";

import app from "../src/app";
import {
  closeApiEndpoints,
  hashUtf8Message,
  loadApiEndpoints,
} from "../src/controllers/api";

const jsonrpcVersion = "2.0";
const okStatus = 200;

// ---------------------------------------------------------------------------
// Helpers
//
// Mirror api.spec.ts, duplicated to keep this file's PROXY_AUTH_PUBKEYS setup
// fully independent of the shared suite. Defined before the setup below,
// since generateKeypair() is called immediately.
// ---------------------------------------------------------------------------

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function generateKeypair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pubkeyHex = spkiDer.slice(SPKI_PREFIX.length).toString("hex");
  return { privateKey, pubkeyHex };
}

function sign(privateKey: crypto.KeyObject, message: Buffer): string {
  return crypto.sign(null, message, privateKey).toString("hex");
}

function b64(data: string | Buffer): string {
  return Buffer.from(data).toString("base64");
}

function sha256hex(data: string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function randomId(): string {
  return crypto.randomBytes(32).toString("hex");
}

function futureExpiresAt(offsetSecs = 3600): string {
  return String(Math.floor(Date.now() / 1000) + offsetSecs);
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

const tempDir = fs.mkdtempSync(path.join(__dirname, "temp-proxy-auth-"));
process.env.APP_DATA = path.join(tempDir, "app-data");

// PROXY_AUTH_PUBKEYS is read once, inside loadApiEndpoints, into a module-level
// variable - it must be set before that call. Jest gives this file its own isolated
// module registry, so this doesn't affect test/api.spec.ts's separate instance.
const allowed = generateKeypair();
const otherAllowed = generateKeypair();
process.env.PROXY_AUTH_PUBKEYS = `${allowed.pubkeyHex}, ${otherAllowed.pubkeyHex}`;

loadApiEndpoints(app);

afterAll(() => {
  closeApiEndpoints();
  return fs.promises.rm(tempDir, { recursive: true, force: true });
});

function invoicePrepareParams(quota?: string) {
  const recipient = generateKeypair();
  const params: Record<string, string> = {
    invoice_id: randomId(),
    expires_at: futureExpiresAt(),
    recipient_pk: recipient.pubkeyHex,
  };
  if (quota !== undefined) params.quota = quota;
  // the quota defaults to 1 also in the signed message
  const message = hashUtf8Message(
    params.invoice_id +
      params.expires_at +
      params.recipient_pk +
      (quota ?? "1"),
  );
  return { params, message };
}

function ackPrepareParams() {
  const sender = generateKeypair();
  const expiresAt = futureExpiresAt();
  const signedTxHash = sha256hex(randomId());
  const transfers = [randomId(), randomId()].map((transferId) => ({
    transferId,
    recipientPk: generateKeypair().pubkeyHex,
    consignmentHash: sha256hex(randomId()),
  }));
  const transferData: Record<string, object> = {};
  for (const t of transfers) {
    transferData[t.transferId] = {
      recipient_pk: t.recipientPk,
      consignment_hash: t.consignmentHash,
      signed_tx: b64(randomId()),
    };
  }
  // transfers sorted by transfer ID, regardless of their order in the request
  let message = sender.pubkeyHex + expiresAt + signedTxHash;
  for (const t of [...transfers].sort((a, b) =>
    a.transferId < b.transferId ? -1 : 1,
  )) {
    message += t.transferId + t.recipientPk + t.consignmentHash;
  }
  return {
    params: {
      transfer_data: transferData,
      expires_at: expiresAt,
      signed_tx_hash: signedTxHash,
      sender_pk: sender.pubkeyHex,
    },
    message: hashUtf8Message(message),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("proxy auth signature over HTTP", () => {
  it("invoice.prepare requires a signature", async () => {
    const { params } = invoicePrepareParams();
    const res = await rpc("invoice.prepare", params);
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual(["signature"]);
  });

  it("invoice.prepare rejects a signature from a non-allowlisted key", async () => {
    const { params, message } = invoicePrepareParams();
    const res = await rpc("invoice.prepare", {
      ...params,
      signature: sign(generateKeypair().privateKey, message),
    });
    expect(res.body.error.code).toBe(-501);
    expect(res.body.error.message).toBe("Invalid proxy auth signature");
  });

  it("invoice.prepare accepts a signature from an allowlisted key", async () => {
    for (const key of [allowed, otherAllowed]) {
      for (const quota of [undefined, "1", "3"]) {
        const { params, message } = invoicePrepareParams(quota);
        const res = await rpc("invoice.prepare", {
          ...params,
          signature: sign(key.privateKey, message),
        });
        expect(res.body.result).toBe(true);
      }
    }
  });

  it("invoice.prepare signature covers the quota", async () => {
    const { params, message } = invoicePrepareParams("1");
    const res = await rpc("invoice.prepare", {
      ...params,
      quota: "2",
      signature: sign(allowed.privateKey, message),
    });
    expect(res.body.error.code).toBe(-501);
  });

  it("ack.prepare rejects a signature from a non-allowlisted key", async () => {
    const { params, message } = ackPrepareParams();
    const res = await rpc("ack.prepare", {
      ...params,
      signature: sign(generateKeypair().privateKey, message),
    });
    expect(res.body.error.code).toBe(-501);
  });

  it("ack.prepare accepts a signature from an allowlisted key", async () => {
    const { params, message } = ackPrepareParams();
    const res = await rpc("ack.prepare", {
      ...params,
      signature: sign(allowed.privateKey, message),
    });
    expect(res.body.result).toBe(true);
  });

  it("refuses to start with an invalid configured pubkey", () => {
    const configured = process.env.PROXY_AUTH_PUBKEYS;
    process.env.PROXY_AUTH_PUBKEYS = `${allowed.pubkeyHex}, not-a-pubkey`;
    try {
      // checked before anything else is set up, so this instance is unaffected
      expect(() => loadApiEndpoints(express())).toThrow(/not-a-pubkey/);
    } finally {
      process.env.PROXY_AUTH_PUBKEYS = configured;
    }
  });
});
