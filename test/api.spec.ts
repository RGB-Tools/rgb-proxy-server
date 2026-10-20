import crypto from "crypto";
import fs from "fs";
import path from "path";
import request from "supertest";

import app from "../src/app";
import {
  deriveTransferId,
  hashUtf8Message,
  parseProxyAuthPubkeys,
  runGC,
  verifyAnyEd25519,
} from "../src/controllers/api";
import {
  ackCleanMessage,
  ackGetMessage,
  ackMessage,
  ackOperation,
  ackPostParams,
  apiClient,
  appTransport,
  b64,
  futureExpiresAt,
  generateKeypair,
  invoiceIdOf,
  newTransfer,
  nowSecs,
  randomId,
  sha256hex,
  sign,
  sleep,
  startApiApp,
} from "./helpers";

const jsonrpcVersion = "2.0";
const okStatus = 200;
const contentTypeForm = "multipart/form-data";
const senderEndpoint = "rpc://sender.example.com/json-rpc";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const retentionGraceSecs = 3600;
const maxQuota = 5;
const maxTransfers = 5;
const { tempDir, appData } = startApiApp("temp-", {
  MAX_UPLOAD_BYTES: String(1024 * 1024),
  RETENTION_GRACE_SECS: String(retentionGraceSecs),
  MAX_QUOTA: String(maxQuota),
  MAX_TRANSFERS: String(maxTransfers),
  // The proof of work stays disabled in this suite (difficulty 0) as the
  // thresholds are never reached, see pow-http.spec.ts for the proof of work
  POW_RATE_THRESHOLD: "1000000",
  POW_GLOBAL_THRESHOLD: "1000000",
});

const {
  rpc,
  upload,
  uploadJson,
  prepareInvoice,
  postConsignment,
  postMedia,
  transferList,
  transferAction,
  invoiceStatus,
  ackPrepare,
  ackGet,
  ackClean,
} = apiClient(appTransport(app));

// ---------------------------------------------------------------------------
// Helpers depending on the data dir
// ---------------------------------------------------------------------------

let fileCounter = 0;

function writeTempFile(content: string | Buffer): string {
  const filePath = path.join(tempDir, `file-${fileCounter++}`);
  fs.writeFileSync(filePath, content);
  return filePath;
}

function storedFiles(dir: "consignments" | "media"): string[] {
  return fs.readdirSync(path.join(appData, dir));
}

// Uploads the content of a file written with writeTempFile
function rpcUpload(
  method: string,
  params: Record<string, string>,
  filePath: string,
) {
  return upload(method, params, fs.readFileSync(filePath));
}

// Params sent as a single JSON-encoded field, as rgb-lib does
function rpcUploadJson(method: string, params: object, filePath: string) {
  return uploadJson(method, params, fs.readFileSync(filePath));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("helpers", () => {
  it("parses comma and whitespace separated pubkey lists", () => {
    expect(parseProxyAuthPubkeys(" aa,\nbb  cc\tdd ")).toEqual([
      "aa",
      "bb",
      "cc",
      "dd",
    ]);
  });

  it("accepts a signature from any configured pubkey", () => {
    const first = generateKeypair();
    const second = generateKeypair();
    const wrong = generateKeypair();
    const message = hashUtf8Message("auth message");
    const signature = sign(second.privateKey, message);
    const wrongSignature = sign(wrong.privateKey, message);
    const pubkeys = [first.pubkeyHex, second.pubkeyHex];

    expect(verifyAnyEd25519(pubkeys, signature, message)).toBe(true);
    expect(verifyAnyEd25519(pubkeys, wrongSignature, message)).toBe(false);
  });

  it("matches the specification example IDs", () => {
    const invoicePk =
      "5c298bf4b0dcf967871778ca682b4de838eb7a201853845c49adc15b10681360";
    const senderPk =
      "e11a179a775712d6763f01de1e10a6141c08f098816aa89a0da333974bf8bc2b";
    const examples = [
      {
        beneficiary:
          "bc:utxob:4vm1CX2Z-K8hMo59-e7dgGBS-Jka7mYn-Xe~yP85-yUiHHxr-aVlYa",
        invoiceId:
          "6ffae5a533bad53bb7ff50152f8a282564fb87429a53384f1b20e88895e7faad",
        transferId:
          "285530722532e2fc802c0ad10bd381d3cca23f01af7d89fb03ec55f734a2a3e7",
      },
      {
        beneficiary:
          "bc:wvout:A8cJ7Ww3-NIzADo3-Tzp_5aD-7CTBWmA-AAAAAAA-AAAAAAA-ALSQkcw",
        invoiceId:
          "4b4ef334f725afa5b09959a62518a09da375b0708c14f760745c241339b8d54f",
        transferId:
          "7ac01c41928a6a114e3320aa4bcbdedb9dd7dd6915fcf993ecd5544fdce1c00f",
      },
    ];
    for (const { beneficiary, invoiceId, transferId } of examples) {
      expect(invoiceIdOf(beneficiary, invoicePk)).toBe(invoiceId);
      expect(deriveTransferId(invoiceId, senderPk)).toBe(transferId);
    }
  });

  it("derives the transfer ID from the invoice ID and the sender pubkey", () => {
    const invoiceId = "a".repeat(64);
    const senderPk = "b".repeat(64);
    expect(deriveTransferId(invoiceId, senderPk)).toBe(
      crypto
        .createHash("sha256")
        .update(
          Buffer.from(
            "rgb-proxy-server/transfer/v1" + invoiceId + senderPk,
            "utf8",
          ),
        )
        .digest("hex"),
    );
  });
});

describe("server.info", () => {
  it("returns the protocol version, clock and limits", async () => {
    const res = await rpc("server.info", {});
    expect(res.body.result.protocol_version).toBe("1.0");
    expect(res.body.result.version).toBeTruthy();
    expect(
      Math.abs(parseInt(res.body.result.current_time) - nowSecs()),
    ).toBeLessThanOrEqual(1);
    expect(res.body.result.max_expiry_secs).toBe("2592000");
    expect(res.body.result.max_quota).toBe(String(maxQuota));
    expect(res.body.result.max_pow_difficulty).toBe("24");
    expect(res.body.result.retention_grace_secs).toBe(
      String(retentionGraceSecs),
    );
    expect(res.body.result.max_file_size).toBe(String(1024 * 1024));
    expect(res.body.result.max_signed_tx_size).toBe("153600");
    expect(res.body.result.max_transfers).toBe(String(maxTransfers));
  });
});

describe("parameter validation", () => {
  it("expires_at in the past or beyond max_expiry_secs is invalid", async () => {
    const info = await rpc("server.info", {});
    const maxExpirySecs = parseInt(info.body.result.max_expiry_secs);
    const recipient = generateKeypair();

    for (const expiresAt of [
      String(nowSecs() - 10),
      futureExpiresAt(maxExpirySecs + 60),
    ]) {
      let res = await rpc("invoice.prepare", {
        invoice_id: randomId(),
        expires_at: expiresAt,
        recipient_pk: recipient.pubkeyHex,
      });
      expect(res.body.error.code).toBe(-200);
      expect(res.body.error.data.fields).toEqual(["expires_at"]);

      const op = ackOperation();
      res = await rpc("ack.prepare", { ...op.params, expires_at: expiresAt });
      expect(res.body.error.code).toBe(-200);
      expect(res.body.error.data.fields).toEqual(["expires_at"]);
    }
  });

  it("missing and invalid errors list all the failing fields", async () => {
    // all the missing fields, which take precedence over the invalid ones
    let res = await rpc("ack.post", { signature: "nothex" });
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.message).toBe("Missing");
    expect(res.body.error.data.fields).toEqual(["transfer_id", "ack"]);

    // all the invalid fields
    res = await rpc("ack.post", {
      transfer_id: "",
      ack: "yes",
      signature: "nothex",
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.message).toBe("Invalid");
    expect(res.body.error.data.fields).toEqual([
      "transfer_id",
      "ack",
      "signature",
    ]);

    // empty or repeated lists
    res = await rpc("ack.prepare", {
      ...ackOperation().params,
      transfer_data: {},
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_data"]);
    const tid = randomId();
    res = await rpc("ack.clean", {
      transfer_ids: [tid, tid],
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_ids"]);

    // fields nested in transfer_data
    const recipient = generateKeypair();
    res = await rpc("ack.prepare", {
      transfer_data: {
        [randomId()]: { recipient_pk: recipient.pubkeyHex },
        [randomId()]: { consignment_hash: sha256hex("c") },
      },
      expires_at: futureExpiresAt(),
      signed_tx_hash: sha256hex("tx"),
    });
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual([
      "consignment_hash",
      "signed_tx",
      "recipient_pk",
      "sender_pk",
    ]);

    res = await rpc("ack.prepare", {
      transfer_data: {
        "not-a-transfer-id": {
          recipient_pk: "nothex",
          consignment_hash: sha256hex("c"),
          signed_tx: "",
        },
      },
      expires_at: "soon",
      signed_tx_hash: sha256hex("tx"),
      sender_pk: recipient.pubkeyHex,
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual([
      "transfer_id",
      "recipient_pk",
      "signed_tx",
      "expires_at",
    ]);

    // hex values must be lowercase
    res = await rpc("consignment.get", {
      transfer_id: randomId().toUpperCase(),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_id"]);

    // multipart requests
    const filePath = writeTempFile("data");
    res = await rpcUpload(
      "consignment.post",
      { transfer_id: randomId(), batch: "maybe", pow_nonce: "" },
      filePath,
    );
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual([
      "invoice_id",
      "sender_transport_endpoint",
      "sender_pk",
      "consignment_hash",
      "file_size",
      "signature",
      "pow_timestamp",
    ]);

    res = await rpcUpload(
      "consignment.post",
      {
        invoice_id: "x",
        transfer_id: randomId(),
        sender_transport_endpoint: senderEndpoint,
        sender_pk: recipient.pubkeyHex,
        consignment_hash: sha256hex("c"),
        batch: "maybe",
        file_size: "4",
        signature: "00".repeat(64),
        pow_timestamp: "yesterday",
        pow_nonce: "x".repeat(65),
      },
      filePath,
    );
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual([
      "invoice_id",
      "batch",
      "pow_timestamp",
      "pow_nonce",
    ]);

    res = await rpcUpload(
      "media.post",
      { transfer_id: randomId(), media_id: "media" },
      filePath,
    );
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual(["file_size", "signature"]);
  });

  it("uploads without a file are refused", async () => {
    const res = await request(app)
      .post("/json-rpc")
      .set("Content-type", contentTypeForm)
      .field("jsonrpc", jsonrpcVersion)
      .field("id", "1")
      .field("method", "media.post")
      .field("params[transfer_id]", randomId())
      .field("params[media_id]", randomId())
      .field("params[file_size]", "4")
      .field("params[signature]", "00".repeat(64))
      .expect(okStatus);
    expect(res.body.error.code).toBe(-301);
  });

  it("uploads exceeding the declared file_size are aborted", async () => {
    const filePath = writeTempFile(Buffer.alloc(512 * 1024, 1));
    const res = await rpcUpload(
      "media.post",
      {
        transfer_id: randomId(),
        media_id: randomId(),
        file_size: "1000",
        signature: "00".repeat(64),
      },
      filePath,
    );
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["file_size"]);
    expect(res.body.id).toBe("1");
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);
  });

  it("uploads smaller than the declared file_size are refused", async () => {
    const filePath = writeTempFile(Buffer.from("data"));
    const res = await rpcUpload(
      "media.post",
      {
        transfer_id: randomId(),
        media_id: randomId(),
        file_size: "5",
        signature: "00".repeat(64),
      },
      filePath,
    );
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["file_size"]);
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);
  });

  it("uploads without a valid file_size are not stored", async () => {
    const filePath = writeTempFile(Buffer.from("data"));
    const writeStream = jest.spyOn(fs, "createWriteStream");
    try {
      let res = await rpcUpload(
        "media.post",
        {
          transfer_id: randomId(),
          media_id: randomId(),
          signature: "00".repeat(64),
        },
        filePath,
      );
      expect(res.body.error.code).toBe(-300);
      expect(res.body.error.data.fields).toEqual(["file_size"]);

      res = await rpcUpload(
        "media.post",
        {
          transfer_id: randomId(),
          media_id: "x",
          file_size: "04",
          signature: "00".repeat(64),
        },
        filePath,
      );
      expect(res.body.error.code).toBe(-200);
      expect(res.body.error.data.fields).toEqual(["media_id", "file_size"]);
      expect(writeStream).not.toHaveBeenCalled();
    } finally {
      writeStream.mockRestore();
    }
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);
  });

  it("uploads sending the file before the params are refused", async () => {
    const res = await request(app)
      .post("/json-rpc")
      .set("Content-type", contentTypeForm)
      .field("jsonrpc", jsonrpcVersion)
      .field("id", "1")
      .field("method", "media.post")
      .attach("file", Buffer.from("data"), "file")
      .field(
        "params",
        JSON.stringify({
          transfer_id: randomId(),
          media_id: randomId(),
          file_size: "4",
          signature: "00".repeat(64),
        }),
      )
      .expect(okStatus);
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["file"]);
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);
  });

  it("uploads exceeding the max upload size are aborted", async () => {
    const filePath = writeTempFile(Buffer.alloc(2 * 1024 * 1024, 1));
    const res = await rpcUpload(
      "consignment.post",
      { file_size: String(2 * 1024 * 1024) },
      filePath,
    );
    expect(res.body.error.code).toBe(-108);
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);
  });

  it("reports malformed requests as JSON-RPC errors", async () => {
    // multipart params that are not valid JSON, the upload is removed
    let res = await request(app)
      .post("/json-rpc")
      .set("Content-type", contentTypeForm)
      .field("jsonrpc", jsonrpcVersion)
      .field("id", "1")
      .field("method", "media.post")
      .field("params", "{not json")
      .attach("file", Buffer.from("data"), "file")
      .expect(okStatus);
    expect(res.body.error.code).toBe(-32700);
    expect(fs.readdirSync(path.join(appData, "tmp"))).toEqual([]);

    // a body that is not valid JSON
    res = await request(app)
      .post("/json-rpc")
      .set("Content-type", "application/json")
      .send("{not json")
      .expect(okStatus);
    expect(res.body.error.code).toBe(-32700);

    // no body
    res = await request(app).post("/json-rpc").expect(okStatus);
    expect(res.body.error.code).toBe(-32600);
  });
});

describe("invoice.prepare", () => {
  it("reserves an invoice and is idempotent", async () => {
    const recipient = generateKeypair();
    const params = {
      invoice_id: randomId(),
      expires_at: futureExpiresAt(),
      recipient_pk: recipient.pubkeyHex,
    };
    let res = await rpc("invoice.prepare", params);
    expect(res.body.result).toBe(true);
    res = await rpc("invoice.prepare", params);
    expect(res.body.result).toBe(false);
    // the quota defaults to 1
    res = await rpc("invoice.prepare", { ...params, quota: "1" });
    expect(res.body.result).toBe(false);
  });

  it("cannot change the reserved data", async () => {
    const invoice = await prepareInvoice("2");
    const other = generateKeypair();
    let res = await rpc("invoice.prepare", {
      invoice_id: invoice.invoiceId,
      expires_at: futureExpiresAt(7200),
      recipient_pk: other.pubkeyHex,
      quota: "3",
    });
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields).toEqual([
      "expires_at",
      "recipient_pk",
      "quota",
    ]);

    res = await rpc("invoice.prepare", {
      invoice_id: invoice.invoiceId,
      expires_at: invoice.expiresAt,
      recipient_pk: invoice.recipient.pubkeyHex,
    });
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields).toEqual(["quota"]);
  });

  it("validates the parameters", async () => {
    let res = await rpc("invoice.prepare", { quota: "1" });
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual([
      "invoice_id",
      "expires_at",
      "recipient_pk",
    ]);

    const recipient = generateKeypair();
    for (const quota of ["0", String(maxQuota + 1), "abc", "01", ""]) {
      res = await rpc("invoice.prepare", {
        invoice_id: randomId(),
        expires_at: futureExpiresAt(),
        recipient_pk: recipient.pubkeyHex,
        quota,
      });
      expect(res.body.error.code).toBe(-200);
      expect(res.body.error.data.fields).toEqual(["quota"]);
    }

    res = await rpc("invoice.prepare", {
      invoice_id: randomId().slice(1),
      expires_at: futureExpiresAt(),
      recipient_pk: recipient.pubkeyHex.toUpperCase(),
      quota: String(maxQuota),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["invoice_id", "recipient_pk"]);

    // the max quota is accepted
    await prepareInvoice(String(maxQuota));
  });
});

describe("invoice.check", () => {
  it("reports unknown, available and full invoices", async () => {
    const invoice = await prepareInvoice("2");
    const unknownId = randomId();

    let res = await rpc("invoice.check", {
      invoice_ids: [invoice.invoiceId, unknownId],
    });
    expect(res.body.result).toEqual({
      [invoice.invoiceId]: { status: "available", pow_difficulty: "0" },
      [unknownId]: { status: "unknown", pow_difficulty: "0" },
    });

    const t1 = newTransfer(invoice.invoiceId);
    expect((await postConsignment(t1, "check 1")).body.result).toBe(true);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");

    const t2 = newTransfer(invoice.invoiceId);
    expect((await postConsignment(t2, "check 2")).body.result).toBe(true);
    res = await rpc("invoice.check", { invoice_ids: [invoice.invoiceId] });
    expect(res.body.result[invoice.invoiceId]).toEqual({
      status: "full",
      pow_difficulty: "0",
    });
  });

  it("validates the invoice IDs", async () => {
    let res = await rpc("invoice.check", {});
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual(["invoice_ids"]);

    res = await rpc("invoice.check", { invoice_ids: [] });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["invoice_ids"]);

    res = await rpc("invoice.check", { invoice_ids: [randomId(), "nothex"] });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["invoice_id"]);
  });

  it("does not consider ack.prepare transfer IDs", async () => {
    const op = await ackPrepare();
    const tid = op.transfers[0].transferId;
    const res = await rpc("invoice.check", { invoice_ids: [tid] });
    expect(res.body.result[tid].status).toBe("unknown");
  });
});

describe("consignment.post / consignment.get", () => {
  it("creates a transfer, is idempotent and returns its data", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    const content = "consignment binary data";
    const consignmentHash = sha256hex("my plaintext consignment");

    let res = await postConsignment(t, content, {
      consignment_hash: consignmentHash,
      batch: "true",
    });
    expect(res.body.result).toBe(true);

    // idempotent, even with the quota now full and a different proof of work
    // (the nonce can include spaces)
    res = await postConsignment(t, content, {
      consignment_hash: consignmentHash,
      batch: "true",
      pow_timestamp: "1",
      pow_nonce: "other nonce",
    });
    expect(res.body.result).toBe(false);

    res = await rpc("consignment.get", { transfer_id: t.transferId });
    expect(res.body.result).toEqual({
      consignment: b64(content),
      sender_transport_endpoint: senderEndpoint,
      sender_pk: t.sender.pubkeyHex,
      consignment_hash: consignmentHash,
      batch: true,
    });
  });

  it("accepts the params as a JSON-encoded field", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    const content = "json params consignment";
    const consignmentHash = sha256hex("json params plaintext");
    const res = await rpcUploadJson(
      "consignment.post",
      {
        invoice_id: invoice.invoiceId,
        transfer_id: t.transferId,
        sender_transport_endpoint: senderEndpoint,
        sender_pk: t.sender.pubkeyHex,
        consignment_hash: consignmentHash,
        batch: false,
        file_size: String(content.length),
        signature: sign(
          t.sender.privateKey,
          hashUtf8Message(t.transferId + consignmentHash + sha256hex(content)),
        ),
        pow_timestamp: String(nowSecs()),
        pow_nonce: "0",
      },
      writeTempFile(content),
    );
    expect(res.body.result).toBe(true);
    const get = await rpc("consignment.get", { transfer_id: t.transferId });
    expect(get.body.result.batch).toBe(false);
  });

  it("consignment.get reports unknown transfers", async () => {
    const res = await rpc("consignment.get", { transfer_id: randomId() });
    expect(res.body.error.code).toBe(-400);
  });

  it("requires a reserved invoice", async () => {
    const t = newTransfer(randomId());
    const res = await postConsignment(t, "no reservation");
    expect(res.body.error.code).toBe(-101);
    expect(res.body.error.message).toBe("Invoice not reserved");
  });

  it("rejects an expired invoice", async () => {
    const invoice = await prepareInvoice(undefined, 1);
    await sleep(1500);
    const t = newTransfer(invoice.invoiceId);
    const res = await postConsignment(t, "expired invoice");
    expect(res.body.error.code).toBe(-111);
    expect(res.body.error.message).toBe("Invoice expired");
  });

  it("verifies the transfer ID derivation", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    // derived from another invoice
    let res = await postConsignment(t, "bad derivation", {
      transfer_id: deriveTransferId(randomId(), t.sender.pubkeyHex),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_id"]);
    // derived from another sender pubkey
    res = await postConsignment(t, "bad derivation", {
      sender_pk: generateKeypair().pubkeyHex,
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_id"]);
  });

  it("verifies the signature over the uploaded file", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    const content = "signed consignment";
    const consignmentHash = sha256hex("signed plaintext");

    // signed by another key
    let res = await postConsignment(t, content, {
      consignment_hash: consignmentHash,
      signature: sign(
        generateKeypair().privateKey,
        hashUtf8Message(t.transferId + consignmentHash + sha256hex(content)),
      ),
    });
    expect(res.body.error.code).toBe(-502);
    expect(res.body.error.message).toBe("Invalid endpoint auth signature");

    // signature for a different file
    res = await postConsignment(t, content, {
      consignment_hash: consignmentHash,
      signature: sign(
        t.sender.privateKey,
        hashUtf8Message(t.transferId + consignmentHash + sha256hex("other")),
      ),
    });
    expect(res.body.error.code).toBe(-502);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");
  });

  it("cannot change an existing transfer", async () => {
    const invoice = await prepareInvoice("2");
    const t = newTransfer(invoice.invoiceId);
    let res = await postConsignment(t, "original");
    expect(res.body.result).toBe(true);

    res = await postConsignment(t, "changed", {
      sender_transport_endpoint: "rpcs://other.example.com/json-rpc",
      consignment_hash: sha256hex("changed plaintext"),
      batch: "true",
    });
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields).toEqual([
      "sender_transport_endpoint",
      "consignment_hash",
      "batch",
      "file",
    ]);

    // a change needs a valid signature to be reported
    res = await postConsignment(t, "changed", {
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-502);
  });

  it("enforces the invoice quota, restored by transfer.delete", async () => {
    const invoice = await prepareInvoice("2");
    const t1 = newTransfer(invoice.invoiceId);
    const t2 = newTransfer(invoice.invoiceId);
    const t3 = newTransfer(invoice.invoiceId);
    expect((await postConsignment(t1, "quota 1")).body.result).toBe(true);
    expect((await postConsignment(t2, "quota 2")).body.result).toBe(true);

    let res = await postConsignment(t3, "quota 3");
    expect(res.body.error.code).toBe(-112);
    expect(res.body.error.message).toBe("Invoice quota exceeded");

    // a retrieved transfer keeps counting towards the quota
    res = await transferAction("retrieved", t1.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);
    res = await postConsignment(t3, "quota 3");
    expect(res.body.error.code).toBe(-112);

    // a deleted one frees its slot
    res = await transferAction("delete", t1.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");
    res = await postConsignment(t3, "quota 3");
    expect(res.body.result).toBe(true);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");
  });

  it("rejects a deleted transfer ID", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    expect((await postConsignment(t, "to delete")).body.result).toBe(true);
    let res = await transferAction("delete", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);

    // also an identical re-post
    res = await postConsignment(t, "to delete");
    expect(res.body.error.code).toBe(-113);
    expect(res.body.error.message).toBe("Transfer ID deleted");
    res = await postConsignment(t, "something else");
    expect(res.body.error.code).toBe(-113);

    res = await rpc("consignment.get", { transfer_id: t.transferId });
    expect(res.body.error.code).toBe(-400);
  });

  it("processes the checks in the specified order", async () => {
    // missing before invalid
    let res = await postConsignment(newTransfer(randomId()), "order", {
      invoice_id: "nothex",
      signature: "",
      pow_nonce: "",
      batch: "",
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual([
      "invoice_id",
      "batch",
      "signature",
      "pow_nonce",
    ]);

    // not reserved before transfer ID derivation and signature
    const unreserved = newTransfer(randomId());
    res = await postConsignment(unreserved, "order", {
      transfer_id: randomId(),
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-101);

    // expired before transfer ID derivation and signature
    const expiring = await prepareInvoice(undefined, 1);
    await sleep(1500);
    res = await postConsignment(newTransfer(expiring.invoiceId), "order", {
      transfer_id: randomId(),
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-111);

    // transfer ID derivation before signature
    const invoice = await prepareInvoice("1");
    res = await postConsignment(newTransfer(invoice.invoiceId), "order", {
      transfer_id: randomId(),
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["transfer_id"]);

    // signature before deleted transfer ID
    const deleted = newTransfer(invoice.invoiceId);
    expect((await postConsignment(deleted, "order")).body.result).toBe(true);
    await transferAction("delete", deleted.transferId, invoice.recipient);
    res = await postConsignment(deleted, "order", {
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-502);

    // deleted transfer ID before quota
    const filler = newTransfer(invoice.invoiceId);
    expect((await postConsignment(filler, "filler")).body.result).toBe(true);
    res = await postConsignment(deleted, "order");
    expect(res.body.error.code).toBe(-113);

    // changed data before quota
    res = await postConsignment(filler, "changed filler");
    expect(res.body.error.code).toBe(-100);

    // identical re-post before everything else
    res = await postConsignment(filler, "filler", {
      signature: "00".repeat(64),
    });
    expect(res.body.result).toBe(false);
  });
});

describe("media.post / media.get", () => {
  it("requires an existing transfer", async () => {
    const t = newTransfer(randomId());
    const res = await postMedia(t, randomId(), "no transfer");
    expect(res.body.error.code).toBe(-402);
    expect(res.body.error.message).toBe("Transfer not found");
  });

  it("stores the media of a transfer, idempotently", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    await postConsignment(t, "media consignment");
    const mediaId = randomId();
    const otherMediaId = randomId();

    let res = await postMedia(t, mediaId, "media binary data");
    expect(res.body.result).toBe(true);
    res = await postMedia(t, mediaId, "media binary data");
    expect(res.body.result).toBe(false);
    res = await postMedia(t, otherMediaId, "other media");
    expect(res.body.result).toBe(true);

    res = await postMedia(t, mediaId, "different media");
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields).toEqual(["file"]);

    res = await rpc("media.get", {
      transfer_id: t.transferId,
      media_id: mediaId,
    });
    expect(res.body.result).toBe(b64("media binary data"));
    res = await rpc("media.get", {
      transfer_id: t.transferId,
      media_id: otherMediaId,
    });
    expect(res.body.result).toBe(b64("other media"));

    res = await rpc("media.get", {
      transfer_id: t.transferId,
      media_id: randomId(),
    });
    expect(res.body.error.code).toBe(-401);
  });

  it("verifies the signature against the transfer sender pubkey", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    await postConsignment(t, "media signature consignment");
    const res = await postMedia(t, randomId(), "media", invoice.recipient);
    expect(res.body.error.code).toBe(-502);
  });
});

describe("transfer.list / transfer.retrieved / transfer.delete", () => {
  it("lists the pending and retrieved transfers of an invoice", async () => {
    const invoice = await prepareInvoice("3");
    let res = await transferList(invoice);
    expect(res.body.result).toEqual({});

    const pending = newTransfer(invoice.invoiceId);
    const retrieved = newTransfer(invoice.invoiceId);
    const deleted = newTransfer(invoice.invoiceId);
    await postConsignment(pending, "list pending");
    await postConsignment(retrieved, "list retrieved");
    await postConsignment(deleted, "list deleted");
    await transferAction("retrieved", retrieved.transferId, invoice.recipient);
    await transferAction("delete", deleted.transferId, invoice.recipient);

    res = await transferList(invoice);
    expect(res.body.result).toEqual({
      [pending.transferId]: "pending",
      [retrieved.transferId]: "retrieved",
    });
  });

  it("transfer.list is authenticated by the invoice pubkey", async () => {
    const invoice = await prepareInvoice();

    let res = await transferList(invoice, generateKeypair());
    expect(res.body.error.code).toBe(-502);

    // invoice not reserved is reported before checking the signature
    res = await transferList(
      { ...invoice, invoiceId: randomId() },
      generateKeypair(),
    );
    expect(res.body.error.code).toBe(-101);

    // the timestamp must be within 300 seconds of the proxy clock
    const timestamp = String(nowSecs() - 301);
    res = await rpc("transfer.list", {
      invoice_id: invoice.invoiceId,
      timestamp,
      signature: sign(
        invoice.recipient.privateKey,
        hashUtf8Message(invoice.invoiceId + timestamp),
      ),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["timestamp"]);
  });

  it("transfer.retrieved deletes the data but keeps the transfer", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    const content = `retrieved consignment ${randomId()}`;
    const mediaContent = `retrieved media ${randomId()}`;
    const mediaId = randomId();
    await postConsignment(t, content);
    await postMedia(t, mediaId, mediaContent);
    expect(storedFiles("consignments")).toContain(sha256hex(content));
    expect(storedFiles("media")).toContain(sha256hex(mediaContent));

    // a delete signature cannot be used to mark it as retrieved
    let res = await transferAction(
      "retrieved",
      t.transferId,
      invoice.recipient,
      "delete",
    );
    expect(res.body.error.code).toBe(-502);
    // the sender cannot mark it as retrieved
    res = await transferAction("retrieved", t.transferId, t.sender);
    expect(res.body.error.code).toBe(-502);

    res = await transferAction("retrieved", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);
    res = await transferAction("retrieved", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(false);

    expect(storedFiles("consignments")).not.toContain(sha256hex(content));
    expect(storedFiles("media")).not.toContain(sha256hex(mediaContent));

    res = await rpc("consignment.get", { transfer_id: t.transferId });
    expect(res.body.error.code).toBe(-403);
    expect(res.body.error.message).toBe("Transfer data retrieved");
    res = await rpc("media.get", {
      transfer_id: t.transferId,
      media_id: mediaId,
    });
    expect(res.body.error.code).toBe(-403);

    // identical re-posts are still recognized
    res = await postConsignment(t, content);
    expect(res.body.result).toBe(false);
    res = await postMedia(t, mediaId, mediaContent);
    expect(res.body.result).toBe(false);
    res = await postConsignment(t, "changed");
    expect(res.body.error.code).toBe(-100);
    res = await postMedia(t, mediaId, "changed");
    expect(res.body.error.code).toBe(-100);
    // new media would never be retrieved
    res = await postMedia(t, randomId(), "new media");
    expect(res.body.error.code).toBe(-403);

    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");
  });

  it("transfer.delete removes the transfer and frees its slot", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    const content = `deleted consignment ${randomId()}`;
    const mediaContent = `deleted media ${randomId()}`;
    const mediaId = randomId();
    await postConsignment(t, content);
    await postMedia(t, mediaId, mediaContent);

    let res = await transferAction(
      "delete",
      t.transferId,
      invoice.recipient,
      "retrieved",
    );
    expect(res.body.error.code).toBe(-502);

    res = await transferAction("delete", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);
    res = await transferAction("delete", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(false);
    // a deleted transfer counts as already handled
    res = await transferAction("retrieved", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(false);

    expect(storedFiles("consignments")).not.toContain(sha256hex(content));
    expect(storedFiles("media")).not.toContain(sha256hex(mediaContent));
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");

    res = await rpc("media.get", {
      transfer_id: t.transferId,
      media_id: mediaId,
    });
    expect(res.body.error.code).toBe(-401);
    res = await postMedia(t, mediaId, mediaContent);
    expect(res.body.error.code).toBe(-402);
  });

  it("transfer.delete also works after transfer.retrieved", async () => {
    const invoice = await prepareInvoice();
    const t = newTransfer(invoice.invoiceId);
    await postConsignment(t, "retrieved then deleted");
    await transferAction("retrieved", t.transferId, invoice.recipient);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");
    const res = await transferAction("delete", t.transferId, invoice.recipient);
    expect(res.body.result).toBe(true);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");
  });

  it("files shared by several transfers are kept while referenced", async () => {
    const invoice = await prepareInvoice("2");
    const t1 = newTransfer(invoice.invoiceId);
    const t2 = newTransfer(invoice.invoiceId);
    const content = `shared consignment ${randomId()}`;
    await postConsignment(t1, content);
    await postConsignment(t2, content);
    await transferAction("delete", t1.transferId, invoice.recipient);
    expect(storedFiles("consignments")).toContain(sha256hex(content));
    const res = await rpc("consignment.get", { transfer_id: t2.transferId });
    expect(res.body.result.consignment).toBe(b64(content));
    await transferAction("retrieved", t2.transferId, invoice.recipient);
    expect(storedFiles("consignments")).not.toContain(sha256hex(content));
  });

  it("report unknown transfers before checking the signature", async () => {
    for (const action of ["retrieved", "delete"] as const) {
      const res = await transferAction(action, randomId(), generateKeypair());
      expect(res.body.error.code).toBe(-402);
    }
    const res = await rpc("transfer.delete", { transfer_id: randomId() });
    expect(res.body.error.code).toBe(-300);
    expect(res.body.error.data.fields).toEqual(["signature"]);
  });
});

describe("ack.prepare", () => {
  it("registers an operation and is idempotent", async () => {
    const op = ackOperation(2);
    let res = await rpc("ack.prepare", op.params);
    expect(res.body.result).toBe(true);
    res = await rpc("ack.prepare", op.params);
    expect(res.body.result).toBe(false);
  });

  it("cannot change a registered operation", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;
    const res = await rpc("ack.prepare", {
      transfer_data: {
        [t1.transferId]: {
          recipient_pk: generateKeypair().pubkeyHex,
          consignment_hash: t1.consignmentHash,
          signed_tx: b64("other tx"),
        },
        [t2.transferId]: {
          recipient_pk: t2.recipient.pubkeyHex,
          consignment_hash: sha256hex("other"),
          signed_tx: t2.signedTx,
        },
      },
      expires_at: futureExpiresAt(7200),
      signed_tx_hash: sha256hex("other tx"),
      sender_pk: generateKeypair().pubkeyHex,
    });
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields.sort()).toEqual(
      [
        "expires_at",
        "signed_tx_hash",
        "sender_pk",
        "recipient_pk",
        "signed_tx",
        "consignment_hash",
      ].sort(),
    );
  });

  it("keeps transfer IDs unique across operations", async () => {
    const op = await ackPrepare(2);
    const [t1] = op.transfers;
    const transferData = op.params.transfer_data as Record<string, object>;

    // subset of the operation
    let res = await rpc("ack.prepare", {
      ...op.params,
      transfer_data: { [t1.transferId]: transferData[t1.transferId] },
    });
    expect(res.body.error.code).toBe(-102);
    expect(res.body.error.message).toBe("Transfer ID in use");

    // partial overlap with a new transfer
    res = await rpc("ack.prepare", {
      ...op.params,
      transfer_data: {
        ...transferData,
        [randomId()]: transferData[t1.transferId],
      },
    });
    expect(res.body.error.code).toBe(-102);

    // overlap across two operations
    const other = await ackPrepare();
    const otherTid = other.transfers[0].transferId;
    res = await rpc("ack.prepare", {
      ...op.params,
      transfer_data: {
        ...transferData,
        [otherTid]: (other.params.transfer_data as Record<string, object>)[
          otherTid
        ],
      },
    });
    expect(res.body.error.code).toBe(-102);
  });

  it("limits the number of transfers", async () => {
    let res = await rpc("ack.prepare", ackOperation(maxTransfers).params);
    expect(res.body.result).toBe(true);
    res = await rpc("ack.prepare", ackOperation(maxTransfers + 1).params);
    expect(res.body.error.code).toBe(-109);
    expect(res.body.error.message).toBe("Too many transfers");
  });

  it("limits the length of the base64 signed TX", async () => {
    const prepare = (signedTx: string) => {
      const op = ackOperation();
      const transferData = op.params.transfer_data as Record<
        string,
        Record<string, string>
      >;
      transferData[op.transfers[0].transferId].signed_tx = signedTx;
      return rpc("ack.prepare", op.params);
    };

    // 115200 bytes encode to exactly 153600 base64 characters
    let res = await prepare(b64(Buffer.alloc(115200)));
    expect(res.body.result).toBe(true);

    res = await prepare(b64(Buffer.alloc(115203)));
    expect(res.body.error.code).toBe(-110);

    res = await prepare("not-base64");
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["signed_tx"]);
  });

  it("aborts a body bigger than max_transfers signed TXs", async () => {
    // max_transfers (5) signed TXs of max_signed_tx_size (153600) each, plus
    // the overhead, stay below 1 MiB
    const res = await rpc("server.info", { padding: "a".repeat(1024 * 1024) });
    expect(res.body.error.code).toBe(-110);
  });
});

describe("ack.post", () => {
  it("verifies the signature and releases the signed TX on a valid ACK", async () => {
    const op = await ackPrepare();
    const [t] = op.transfers;

    let res = await rpc("ack.post", {
      ...ackPostParams(t, true),
      signature: sign(
        generateKeypair().privateKey,
        ackMessage(t.transferId, true, t.consignmentHash),
      ),
    });
    expect(res.body.error.code).toBe(-503);

    res = await rpc("ack.post", ackPostParams(t, true));
    expect(res.body.result).toEqual({
      result: true,
      sender_pk: op.sender.pubkeyHex,
      signed_tx: t.signedTx,
      signed_tx_hash: op.signedTxHash,
      expires_at: op.expiresAt,
    });

    // idempotent
    res = await rpc("ack.post", ackPostParams(t, true));
    expect(res.body.result).toEqual({
      result: false,
      sender_pk: op.sender.pubkeyHex,
      signed_tx: t.signedTx,
      signed_tx_hash: op.signedTxHash,
      expires_at: op.expiresAt,
    });

    // cannot change, only reported to the recipient
    res = await rpc("ack.post", ackPostParams(t, false));
    expect(res.body.error.code).toBe(-100);
    expect(res.body.error.data.fields).toEqual(["ack", "signature"]);
    for (const ack of [true, false]) {
      res = await rpc("ack.post", {
        ...ackPostParams(t, ack),
        signature: "00".repeat(64),
      });
      expect(res.body.error.code).toBe(-503);
    }
  });

  it("reports unknown transfer IDs", async () => {
    const res = await rpc("ack.post", {
      transfer_id: randomId(),
      ack: true,
      signature: "00".repeat(64),
    });
    expect(res.body.error.code).toBe(-104);
  });

  it("removes the signed TX on a valid NACK", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;
    let res = await rpc("ack.post", ackPostParams(t1, false));
    expect(res.body.result).toEqual({
      result: true,
      expires_at: op.expiresAt,
    });
    res = await rpc("ack.post", ackPostParams(t1, false));
    expect(res.body.result).toEqual({
      result: false,
      expires_at: op.expiresAt,
    });
    res = await rpc("ack.post", ackPostParams(t2, true));
    expect(res.body.result.signed_tx).toBeUndefined();
    expect(res.body.result.expires_at).toBe(op.expiresAt);

    // no signed TX left to remove
    res = await ackClean(op);
    expect(res.body.result).toBe(false);
  });

  it("does not release the TX until all batch transfers have been acked", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;

    let res = await rpc("ack.post", ackPostParams(t1, true));
    expect(res.body.result).toEqual({
      result: true,
      sender_pk: op.sender.pubkeyHex,
      signed_tx_hash: op.signedTxHash,
      expires_at: op.expiresAt,
    });

    res = await rpc("ack.post", ackPostParams(t2, true));
    expect(res.body.result.signed_tx).toBe(t2.signedTx);

    res = await rpc("ack.post", ackPostParams(t1, true));
    expect(res.body.result.result).toBe(false);
    expect(res.body.result.signed_tx).toBe(t1.signedTx);
  });

  it("rejects ACKs past the expiration, NACKs stay idempotent", async () => {
    const op = await ackPrepare(3, 2);
    const [acked, nacked, late] = op.transfers;
    let res = await rpc("ack.post", ackPostParams(nacked, false));
    expect(res.body.result.result).toBe(true);
    res = await rpc("ack.post", ackPostParams(acked, true));
    expect(res.body.result.result).toBe(true);

    await sleep(2500);

    res = await rpc("ack.post", ackPostParams(late, true));
    expect(res.body.error.code).toBe(-105);
    // the TX was never released, so the expiration is reported
    res = await rpc("ack.post", ackPostParams(acked, true));
    expect(res.body.error.code).toBe(-105);
    res = await rpc("ack.post", ackPostParams(nacked, false));
    expect(res.body.result.result).toBe(false);
  });

  it("a released TX can be fetched again past the expiration", async () => {
    const op = await ackPrepare(1, 2);
    const [t] = op.transfers;
    let res = await rpc("ack.post", ackPostParams(t, true));
    expect(res.body.result.signed_tx).toBe(t.signedTx);
    await sleep(2500);
    res = await rpc("ack.post", ackPostParams(t, true));
    expect(res.body.result.result).toBe(false);
    expect(res.body.result.signed_tx).toBe(t.signedTx);
  });
});

describe("ack.get", () => {
  it("requires sender authentication and returns the ack data", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;

    let res = await ackGet(op);
    // transfers not responded to yet are left out of the response
    expect(res.body.result).toEqual({ acks: {}, signatures: {} });

    const ack = ackPostParams(t1, true);
    const nack = ackPostParams(t2, false);
    await rpc("ack.post", ack);
    await rpc("ack.post", nack);

    res = await ackGet(op);
    expect(res.body.result).toEqual({
      acks: { [t1.transferId]: true, [t2.transferId]: false },
      signatures: {
        [t1.transferId]: ack.signature,
        [t2.transferId]: nack.signature,
      },
    });

    // a subset of the operation
    res = await ackGet(op, [t2.transferId]);
    expect(res.body.result).toEqual({
      acks: { [t2.transferId]: false },
      signatures: { [t2.transferId]: nack.signature },
    });

    const timestamp = String(nowSecs());
    const ids = [t1.transferId];
    res = await rpc("ack.get", {
      transfer_ids: ids,
      timestamp,
      signature: sign(t1.recipient.privateKey, ackGetMessage(ids, timestamp)),
    });
    expect(res.body.error.code).toBe(-502);
  });

  it("signature covers the sorted transfer IDs and a recent timestamp", async () => {
    const op = await ackPrepare(2);
    const [idA, idB] = op.transfers.map((t) => t.transferId).sort();

    // message built in request order instead of sorted
    let timestamp = String(nowSecs());
    let res = await rpc("ack.get", {
      transfer_ids: [idB, idA],
      timestamp,
      signature: sign(
        op.sender.privateKey,
        hashUtf8Message(idB + idA + timestamp),
      ),
    });
    expect(res.body.error.code).toBe(-502);

    res = await rpc("ack.get", {
      transfer_ids: [idB, idA],
      timestamp,
      signature: sign(
        op.sender.privateKey,
        hashUtf8Message(idA + idB + timestamp),
      ),
    });
    expect(res.body.result).toEqual({ acks: {}, signatures: {} });

    timestamp = String(nowSecs() + 301);
    res = await rpc("ack.get", {
      transfer_ids: [idA, idB],
      timestamp,
      signature: sign(
        op.sender.privateKey,
        hashUtf8Message(idA + idB + timestamp),
      ),
    });
    expect(res.body.error.code).toBe(-200);
    expect(res.body.error.data.fields).toEqual(["timestamp"]);
  });

  it("transfer IDs must belong to a single known operation", async () => {
    const op1 = await ackPrepare();
    const op2 = await ackPrepare();
    let res = await ackGet(op1, [
      op1.transfers[0].transferId,
      op2.transfers[0].transferId,
    ]);
    expect(res.body.error.code).toBe(-104);
    res = await ackGet(op1, [randomId()]);
    expect(res.body.error.code).toBe(-104);
  });
});

describe("ack.clean", () => {
  it("removes the signed TXs and is authenticated by sender_pk", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;
    const ids = op.transfers.map((t) => t.transferId);

    let res = await rpc("ack.clean", {
      transfer_ids: ids,
      signature: sign(generateKeypair().privateKey, ackCleanMessage(ids)),
    });
    expect(res.body.error.code).toBe(-502);

    // all the transfers of the operation are required
    res = await rpc("ack.clean", {
      transfer_ids: [t1.transferId],
      signature: sign(op.sender.privateKey, ackCleanMessage([t1.transferId])),
    });
    expect(res.body.error.code).toBe(-104);

    res = await ackClean(op);
    expect(res.body.result).toBe(true);
    res = await ackClean(op);
    expect(res.body.result).toBe(false);

    // the operation is kept, but no TX is released anymore
    res = await rpc("ack.post", ackPostParams(t1, true));
    expect(res.body.result.result).toBe(true);
    res = await rpc("ack.post", ackPostParams(t2, true));
    expect(res.body.result.result).toBe(true);
    expect(res.body.result.signed_tx).toBeUndefined();
  });

  it("is allowed after partial responses", async () => {
    const op = await ackPrepare(2);
    const [t1, t2] = op.transfers;
    await rpc("ack.post", ackPostParams(t1, true));
    let res = await ackClean(op);
    expect(res.body.result).toBe(true);

    // the TX is not released once every transfer has been ACKed
    res = await rpc("ack.post", ackPostParams(t2, true));
    expect(res.body.result.result).toBe(true);
    expect(res.body.result.signed_tx).toBeUndefined();
    res = await rpc("ack.post", ackPostParams(t1, true));
    expect(res.body.result.signed_tx).toBeUndefined();
  });

  it("fails once every transfer has been ACKed", async () => {
    const op = await ackPrepare(2);
    for (const t of op.transfers) await rpc("ack.post", ackPostParams(t, true));
    const res = await ackClean(op);
    expect(res.body.error.code).toBe(-107);
    expect(res.body.error.message).toBe("Already acked");
  });

  it("is atomic with respect to ack.post", async () => {
    for (let i = 0; i < 10; i++) {
      const op = await ackPrepare(1);
      const [t] = op.transfers;
      // concurrent calls: the requests are interleaved by the HTTP layer
      const [clean, post] = await Promise.all([
        ackClean(op),
        rpc("ack.post", ackPostParams(t, true)),
      ]);
      expect(post.body.result.result).toBe(true);
      const cleaned = clean.body.result === true;
      expect({
        clean: cleaned ? true : clean.body.error.code,
        signedTx: post.body.result.signed_tx,
      }).toEqual(
        cleaned
          ? // the TX was removed before the ACK was registered
            { clean: true, signedTx: undefined }
          : // the ACK was registered first, the TX was released
            { clean: -107, signedTx: t.signedTx },
      );
    }
  });
});

describe("data retention", () => {
  it("never deletes a reservation before its expiration", async () => {
    const invoice = await prepareInvoice(undefined, 600);
    const t = newTransfer(invoice.invoiceId);
    await postConsignment(t, "kept until expiration");
    await transferAction("delete", t.transferId, invoice.recipient);

    runGC(nowSecs() + 590);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("available");
    // the record of the deleted transfer is kept too
    const res = await postConsignment(t, "kept until expiration");
    expect(res.body.error.code).toBe(-113);
    const list = await transferList(invoice);
    expect(list.body.result).toEqual({});
  });

  it("deletes the invoice data at the expiration if no transfer is pending", async () => {
    const invoice = await prepareInvoice("3", 600);
    const retrieved = newTransfer(invoice.invoiceId);
    const deleted = newTransfer(invoice.invoiceId);
    await postConsignment(retrieved, "retrieved before expiration");
    await postConsignment(deleted, "deleted before expiration");
    await transferAction("retrieved", retrieved.transferId, invoice.recipient);
    await transferAction("delete", deleted.transferId, invoice.recipient);

    runGC(nowSecs() + 610);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("unknown");
    let res = await transferList(invoice);
    expect(res.body.error.code).toBe(-101);
    res = await transferAction(
      "retrieved",
      retrieved.transferId,
      invoice.recipient,
    );
    expect(res.body.error.code).toBe(-402);
    res = await transferAction("delete", deleted.transferId, invoice.recipient);
    expect(res.body.error.code).toBe(-402);

    // the invoice ID is free again
    res = await rpc("invoice.prepare", {
      invoice_id: invoice.invoiceId,
      expires_at: futureExpiresAt(),
      recipient_pk: generateKeypair().pubkeyHex,
    });
    expect(res.body.result).toBe(true);
  });

  it("keeps pending transfers until retrieved, within the retention grace", async () => {
    const invoice = await prepareInvoice("2", 600);
    const t1 = newTransfer(invoice.invoiceId);
    const t2 = newTransfer(invoice.invoiceId);
    const content = `pending past expiration ${randomId()}`;
    const mediaId = randomId();
    await postConsignment(t1, content);
    await postConsignment(t2, "second pending past expiration");
    await postMedia(t1, mediaId, `pending media ${randomId()}`);

    // expired, with pending transfers: everything is kept
    runGC(nowSecs() + 610);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");
    let res = await rpc("consignment.get", { transfer_id: t1.transferId });
    expect(res.body.result.consignment).toBe(b64(content));
    res = await rpc("media.get", {
      transfer_id: t1.transferId,
      media_id: mediaId,
    });
    expect(res.body.result).toBeTruthy();
    res = await transferList(invoice);
    expect(Object.keys(res.body.result).length).toBe(2);

    // one left pending
    await transferAction("retrieved", t1.transferId, invoice.recipient);
    runGC(nowSecs() + 620);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");

    // none left pending: all the invoice data can go
    await transferAction("delete", t2.transferId, invoice.recipient);
    runGC(nowSecs() + 630);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("unknown");
  });

  it("deletes pending transfers once the retention grace has passed", async () => {
    const invoice = await prepareInvoice(undefined, 600);
    const t = newTransfer(invoice.invoiceId);
    const content = `never retrieved ${randomId()}`;
    const mediaContent = `never retrieved media ${randomId()}`;
    await postConsignment(t, content);
    await postMedia(t, randomId(), mediaContent);

    runGC(nowSecs() + 600 + retentionGraceSecs - 10);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("full");

    runGC(nowSecs() + 600 + retentionGraceSecs + 10);
    expect(await invoiceStatus(invoice.invoiceId)).toBe("unknown");
    const res = await rpc("consignment.get", { transfer_id: t.transferId });
    expect(res.body.error.code).toBe(-400);
    expect(storedFiles("consignments")).not.toContain(sha256hex(content));
    expect(storedFiles("media")).not.toContain(sha256hex(mediaContent));
  });

  it("keeps ACK data and released TXs until the retention grace, regardless of ack.get", async () => {
    const op = await ackPrepare(1, 2);
    const [t] = op.transfers;
    const ack = ackPostParams(t, true);
    let res = await rpc("ack.post", ack);
    expect(res.body.result.signed_tx).toBe(t.signedTx);
    const graceEnd = Number(op.expiresAt) + retentionGraceSecs;

    // retrieved after the expiration: the data is kept anyway
    await sleep(2500);
    runGC();
    res = await ackGet(op);
    expect(res.body.result.signatures[t.transferId]).toBe(ack.signature);
    runGC(graceEnd - 10);
    res = await ackGet(op);
    expect(res.body.result.acks).toEqual({ [t.transferId]: true });
    expect(res.body.result.signatures[t.transferId]).toBe(ack.signature);
    // the released TX can still be retrieved by posting the ACK again
    res = await rpc("ack.post", ack);
    expect(res.body.result).toEqual({
      result: false,
      sender_pk: op.sender.pubkeyHex,
      signed_tx: t.signedTx,
      signed_tx_hash: op.signedTxHash,
      expires_at: op.expiresAt,
    });

    // past the retention grace the operation is gone
    runGC(graceEnd + 10);
    res = await ackGet(op);
    expect(res.body.error.code).toBe(-104);
    res = await rpc("ack.post", ack);
    expect(res.body.error.code).toBe(-104);
  });

  it("keeps unretrieved ACK data for up to the retention grace", async () => {
    const op = await ackPrepare(2, 600);
    const [t1] = op.transfers;
    const ack = ackPostParams(t1, true);
    await rpc("ack.post", ack);

    runGC(nowSecs() + 600 + retentionGraceSecs - 10);
    let res = await ackGet(op);
    expect(res.body.result.signatures[t1.transferId]).toBe(ack.signature);

    runGC(nowSecs() + 600 + retentionGraceSecs + 10);
    res = await ackGet(op);
    expect(res.body.error.code).toBe(-104);
  });

  it("drops unreleased signed TXs at the expiration, keeps the operation until the retention grace", async () => {
    // partially ACKed: the TXs that were not released are dropped
    const op = await ackPrepare(2, 600);
    const [t1, t2] = op.transfers;
    const graceEnd = Number(op.expiresAt) + retentionGraceSecs;
    let res = await rpc("ack.post", ackPostParams(t1, true));
    expect(res.body.result.signed_tx).toBeUndefined();
    runGC(Number(op.expiresAt) + 10);
    // the proxy clock hasn't reached the expiration, so the ACK is accepted,
    // but the TX is gone
    res = await rpc("ack.post", ackPostParams(t2, true));
    expect(res.body.result.result).toBe(true);
    expect(res.body.result.signed_tx).toBeUndefined();
    res = await ackGet(op);
    expect(res.body.result.acks).toEqual({
      [t1.transferId]: true,
      [t2.transferId]: true,
    });
    runGC(graceEnd + 10);
    res = await ackGet(op);
    expect(res.body.error.code).toBe(-104);

    // no responses: the TXs are dropped, the operation is kept
    const op2 = await ackPrepare(1, 600);
    const graceEnd2 = Number(op2.expiresAt) + retentionGraceSecs;
    runGC(Number(op2.expiresAt) + 10);
    res = await ackGet(op2);
    expect(res.body.result).toEqual({ acks: {}, signatures: {} });
    res = await ackClean(op2);
    expect(res.body.result).toBe(false);
    runGC(graceEnd2 - 10);
    res = await ackGet(op2);
    expect(res.body.result).toEqual({ acks: {}, signatures: {} });
    runGC(graceEnd2 + 10);
    res = await ackGet(op2);
    expect(res.body.error.code).toBe(-104);
  });
});
