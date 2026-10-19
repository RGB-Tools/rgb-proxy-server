import crypto from "crypto";
import request from "supertest";

import type { Application } from "express";

import { deriveTransferId, hashUtf8Message } from "../src/controllers/api";

// Helpers shared by the suites exercising the server as a client would,
// either in-process (supertest) or as a running server (fetch), see Transport

// ---------------------------------------------------------------------------
// Crypto and misc helpers
// ---------------------------------------------------------------------------

const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface Keypair {
  privateKey: crypto.KeyObject;
  pubkeyHex: string;
}

export function generateKeypair(): Keypair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const pubkeyHex = spkiDer.subarray(SPKI_PREFIX.length).toString("hex");
  return { privateKey, pubkeyHex };
}

export function sign(privateKey: crypto.KeyObject, message: Buffer): string {
  return crypto.sign(null, message, privateKey).toString("hex");
}

export function sha256hex(data: string | Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function randomId(): string {
  return crypto.randomBytes(32).toString("hex");
}

export function invoiceIdOf(beneficiary: string, invoicePk: string): string {
  return sha256hex("rgb-proxy-server/invoice/v1" + beneficiary + invoicePk);
}

export function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

export function futureExpiresAt(offsetSecs = 3600): string {
  return String(nowSecs() + offsetSecs);
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Polls until the condition holds, returning whether it did within the timeout
export async function waitFor(
  condition: () => boolean,
  timeoutMs: number,
): Promise<boolean> {
  const start = Date.now();
  while (!condition() && Date.now() - start < timeoutMs) await sleep(50);
  return condition();
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

// Both methods resolve to the JSON-RPC response body. Params of uploads are
// sent as `params[<name>]` form fields, next to the `file`
export interface Transport {
  rpc(method: string, params: object): Promise<any>;
  upload(
    method: string,
    params: Record<string, string>,
    content: string | Buffer,
  ): Promise<any>;
}

// Talks to the Express app directly, without listening on a port
export function appTransport(app: Application): Transport {
  return {
    async rpc(method, params) {
      const res = await request(app)
        .post("/json-rpc")
        .send({ jsonrpc: "2.0", id: "1", method, params })
        .expect(200);
      return res.body;
    },
    async upload(method, params, content) {
      let req = request(app)
        .post("/json-rpc")
        .set("Content-type", "multipart/form-data")
        .field("jsonrpc", "2.0")
        .field("id", "1")
        .field("method", method);
      for (const [k, v] of Object.entries(params)) {
        req = req.field(`params[${k}]`, v);
      }
      const res = await req
        .attach("file", Buffer.from(content), "file")
        .expect(200);
      return res.body;
    },
  };
}

// Talks to a running server
export function httpTransport(baseUrl: string): Transport {
  const url = `${baseUrl}/json-rpc`;
  return {
    async rpc(method, params) {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "1", method, params }),
      });
      return res.json();
    },
    async upload(method, params, content) {
      const form = new FormData();
      form.append("jsonrpc", "2.0");
      form.append("id", "1");
      form.append("method", method);
      for (const [k, v] of Object.entries(params)) {
        form.append(`params[${k}]`, v);
      }
      const bytes =
        typeof content === "string" ? content : new Uint8Array(content);
      form.append("file", new Blob([bytes]), "file");
      const res = await fetch(url, { method: "POST", body: form });
      return res.json();
    },
  };
}

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

export interface Invoice {
  invoiceId: string;
  recipient: Keypair;
  expiresAt: string;
}

export interface Transfer {
  invoiceId: string;
  transferId: string;
  sender: Keypair;
}

export interface AckTransfer {
  transferId: string;
  recipient: Keypair;
  consignmentHash: string;
  signedTx: string;
}

export interface AckOperation {
  sender: Keypair;
  transfers: AckTransfer[];
  signedTxHash: string;
  expiresAt: string;
  params: Record<string, unknown>;
}

export function newTransfer(invoiceId: string): Transfer {
  const sender = generateKeypair();
  return {
    invoiceId,
    transferId: deriveTransferId(invoiceId, sender.pubkeyHex),
    sender,
  };
}

export function ackOperation(count = 1, expiresInSecs = 3600): AckOperation {
  const sender = generateKeypair();
  const transfers = Array.from({ length: count }, (_, i) => ({
    transferId: randomId(),
    recipient: generateKeypair(),
    consignmentHash: sha256hex(randomId()),
    signedTx: Buffer.from(`encrypted signed tx ${i} ${randomId()}`).toString(
      "base64",
    ),
  }));
  const signedTxHash = sha256hex(randomId());
  const expiresAt = futureExpiresAt(expiresInSecs);
  const transferData: Record<string, object> = {};
  for (const t of transfers) {
    transferData[t.transferId] = {
      recipient_pk: t.recipient.pubkeyHex,
      consignment_hash: t.consignmentHash,
      signed_tx: t.signedTx,
    };
  }
  return {
    sender,
    transfers,
    signedTxHash,
    expiresAt,
    params: {
      transfer_data: transferData,
      expires_at: expiresAt,
      signed_tx_hash: signedTxHash,
      sender_pk: sender.pubkeyHex,
    },
  };
}

export function ackPostParams(t: AckTransfer, ack: boolean) {
  return {
    transfer_id: t.transferId,
    ack,
    signature: sign(
      t.recipient.privateKey,
      hashUtf8Message(
        t.transferId + (ack ? "true" : "false") + t.consignmentHash,
      ),
    ),
  };
}

// The API calls the suites need, on top of a transport. They return the
// JSON-RPC response bodies, expecting success only where a helper says so
export function apiClient(transport: Transport) {
  const { rpc, upload } = transport;

  async function prepareInvoice(
    quota?: string,
    expiresInSecs = 3600,
  ): Promise<Invoice> {
    const recipient = generateKeypair();
    const invoiceId = invoiceIdOf(randomId(), recipient.pubkeyHex);
    const expiresAt = futureExpiresAt(expiresInSecs);
    const params: Record<string, string> = {
      invoice_id: invoiceId,
      expires_at: expiresAt,
      recipient_pk: recipient.pubkeyHex,
    };
    if (quota !== undefined) params.quota = quota;
    const res = await rpc("invoice.prepare", params);
    expect(res.result).toBe(true);
    return { invoiceId, recipient, expiresAt };
  }

  // Posts a consignment with the given content, signed by the sender
  async function postConsignment(t: Transfer, content: string) {
    const consignmentHash = sha256hex("plaintext " + content);
    return upload(
      "consignment.post",
      {
        invoice_id: t.invoiceId,
        transfer_id: t.transferId,
        sender_transport_endpoint: "rpc://sender.example.com/json-rpc",
        sender_pk: t.sender.pubkeyHex,
        consignment_hash: consignmentHash,
        batch: "false",
        file_size: String(Buffer.byteLength(content)),
        pow_timestamp: String(nowSecs()),
        pow_nonce: "0",
        signature: sign(
          t.sender.privateKey,
          hashUtf8Message(t.transferId + consignmentHash + sha256hex(content)),
        ),
      },
      content,
    );
  }

  async function postMedia(t: Transfer, mediaId: string, content: string) {
    return upload(
      "media.post",
      {
        transfer_id: t.transferId,
        media_id: mediaId,
        file_size: String(Buffer.byteLength(content)),
        signature: sign(
          t.sender.privateKey,
          hashUtf8Message(t.transferId + mediaId + sha256hex(content)),
        ),
      },
      content,
    );
  }

  async function transferList(invoice: Invoice) {
    const timestamp = String(nowSecs());
    return rpc("transfer.list", {
      invoice_id: invoice.invoiceId,
      timestamp,
      signature: sign(
        invoice.recipient.privateKey,
        hashUtf8Message(invoice.invoiceId + timestamp),
      ),
    });
  }

  async function transferAction(
    action: "retrieved" | "delete",
    transferId: string,
    signer: Keypair,
  ) {
    return rpc(`transfer.${action}`, {
      transfer_id: transferId,
      signature: sign(signer.privateKey, hashUtf8Message(transferId + action)),
    });
  }

  async function invoiceStatus(invoiceId: string) {
    const res = await rpc("invoice.check", { invoice_ids: [invoiceId] });
    return res.result[invoiceId].status;
  }

  async function ackPrepare(count = 1, expiresInSecs = 3600) {
    const op = ackOperation(count, expiresInSecs);
    const res = await rpc("ack.prepare", op.params);
    expect(res.result).toBe(true);
    return op;
  }

  async function ackPost(t: AckTransfer, ack: boolean) {
    return rpc("ack.post", ackPostParams(t, ack));
  }

  async function ackGet(op: AckOperation, transferIds?: string[]) {
    const ids = transferIds ?? op.transfers.map((t) => t.transferId);
    const timestamp = String(nowSecs());
    return rpc("ack.get", {
      transfer_ids: ids,
      timestamp,
      signature: sign(
        op.sender.privateKey,
        hashUtf8Message([...ids].sort().join("") + timestamp),
      ),
    });
  }

  return {
    rpc,
    upload,
    prepareInvoice,
    postConsignment,
    postMedia,
    transferList,
    transferAction,
    invoiceStatus,
    ackPrepare,
    ackPost,
    ackGet,
  };
}
