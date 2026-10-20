import crypto from "crypto";
import type { Application } from "express";
import fs from "fs";
import path from "path";
import request from "supertest";

import app from "../src/app";
import {
  closeApiEndpoints,
  deriveTransferId,
  hashUtf8Message,
  loadApiEndpoints,
} from "../src/controllers/api";

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

export function b64(data: string | Buffer): string {
  return Buffer.from(data).toString("base64");
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

export function ackMessage(
  transferId: string,
  ack: boolean,
  consignmentHash: string,
): Buffer {
  return hashUtf8Message(
    transferId + (ack ? "true" : "false") + consignmentHash,
  );
}

export function ackCleanMessage(transferIds: string[]): Buffer {
  return hashUtf8Message([...transferIds].sort().join(""));
}

export function ackGetMessage(
  transferIds: string[],
  timestamp: string,
): Buffer {
  return hashUtf8Message([...transferIds].sort().join("") + timestamp);
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

// Whether the files held open by this process can be listed (Linux)
export const hasProcFds = fs.existsSync("/proc/self/fd");

// Files under the directory this process holds open, including the ones
// already deleted (a leaked descriptor on an unlinked file isn't in the dir)
export function openFilesUnder(dir: string): string[] {
  const prefix = fs.realpathSync(dir) + path.sep;
  const open: string[] = [];
  for (const fd of fs.readdirSync("/proc/self/fd")) {
    let target: string;
    try {
      target = fs.readlinkSync(path.join("/proc/self/fd", fd));
    } catch {
      continue; // closed meanwhile, e.g. the descriptor of the listing itself
    }
    target = target.replace(/ \(deleted\)$/, "");
    if (target.startsWith(prefix)) open.push(target);
  }
  return open;
}

// ---------------------------------------------------------------------------
// Suite setup
// ---------------------------------------------------------------------------

// Creates a temp dir next to the tests, removed once the suite is done
export function useTempDir(prefix: string): string {
  const tempDir = fs.mkdtempSync(path.join(__dirname, prefix));
  afterAll(() => fs.promises.rm(tempDir, { recursive: true, force: true }));
  return tempDir;
}

// Loads the API endpoints on the app with its own data dir, closing them once
// the suite is done. The environment is set first, as the configuration is
// read when loading. Jest gives every suite its own module registry, so suites
// don't share the API state
export function startApiApp(prefix: string, env: Record<string, string> = {}) {
  const tempDir = fs.mkdtempSync(path.join(__dirname, prefix));
  const appData = path.join(tempDir, "app-data");
  process.env.APP_DATA = appData;
  Object.assign(process.env, env);
  loadApiEndpoints(app);
  afterAll(() => {
    closeApiEndpoints();
    return fs.promises.rm(tempDir, { recursive: true, force: true });
  });
  return { app, tempDir, appData };
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

// Methods resolve to an object whose `body` is the JSON-RPC response. Params
// of uploads are sent as `params[<name>]` form fields next to the `file`, or,
// for uploadJson, as a single JSON-encoded `params` field as rgb-lib does
// Same shape as the supertest responses, whose body is untyped as well
export interface RpcResponse {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body: any;
}

export interface Transport {
  rpc(method: string, params: object): Promise<RpcResponse>;
  upload(
    method: string,
    params: Record<string, string>,
    content: string | Buffer,
  ): Promise<RpcResponse>;
  uploadJson(
    method: string,
    params: object,
    content: string | Buffer,
  ): Promise<RpcResponse>;
}

// Talks to the Express app directly, without listening on a port
export function appTransport(app: Application): Transport {
  const uploadRequest = (method: string) =>
    request(app)
      .post("/json-rpc")
      .set("Content-type", "multipart/form-data")
      .field("jsonrpc", "2.0")
      .field("id", "1")
      .field("method", method);
  return {
    rpc: (method, params) =>
      request(app)
        .post("/json-rpc")
        .send({ jsonrpc: "2.0", id: "1", method, params })
        .expect(200),
    upload(method, params, content) {
      let req = uploadRequest(method);
      for (const [k, v] of Object.entries(params)) {
        req = req.field(`params[${k}]`, v);
      }
      return req.attach("file", Buffer.from(content), "file").expect(200);
    },
    uploadJson: (method, params, content) =>
      uploadRequest(method)
        .field("params", JSON.stringify(params))
        .attach("file", Buffer.from(content), "file")
        .expect(200),
  };
}

// Talks to a running server
export function httpTransport(baseUrl: string): Transport {
  const post = async (init: { headers?: HeadersInit; body: BodyInit }) => {
    const res = await fetch(`${baseUrl}/json-rpc`, { method: "POST", ...init });
    return { body: await res.json() };
  };
  const uploadForm = (
    method: string,
    content: string | Buffer,
    fields: Record<string, string>,
  ) => {
    const form = new FormData();
    form.append("jsonrpc", "2.0");
    form.append("id", "1");
    form.append("method", method);
    for (const [k, v] of Object.entries(fields)) form.append(k, v);
    const bytes =
      typeof content === "string" ? content : new Uint8Array(content);
    form.append("file", new Blob([bytes]), "file");
    return post({ body: form });
  };
  return {
    rpc: (method, params) =>
      post({
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: "1", method, params }),
      }),
    upload: (method, params, content) =>
      uploadForm(
        method,
        content,
        Object.fromEntries(
          Object.entries(params).map(([k, v]) => [`params[${k}]`, v]),
        ),
      ),
    uploadJson: (method, params, content) =>
      uploadForm(method, content, { params: JSON.stringify(params) }),
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
  // The content of the file of ack.prepare: transfer ID to signed TX
  signedTxs: Record<string, string>;
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
    signedTx: b64(`encrypted signed tx ${i} ${randomId()}`),
  }));
  const signedTxHash = sha256hex(randomId());
  const expiresAt = futureExpiresAt(expiresInSecs);
  const transferData: Record<string, object> = {};
  const signedTxs: Record<string, string> = {};
  for (const t of transfers) {
    transferData[t.transferId] = {
      recipient_pk: t.recipient.pubkeyHex,
      consignment_hash: t.consignmentHash,
    };
    signedTxs[t.transferId] = t.signedTx;
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
    signedTxs,
  };
}

export function ackPostParams(t: AckTransfer, ack: boolean) {
  return {
    transfer_id: t.transferId,
    ack,
    signature: sign(
      t.recipient.privateKey,
      ackMessage(t.transferId, ack, t.consignmentHash),
    ),
  };
}

// The API calls the suites need, on top of a transport. They return the
// transport's responses, expecting success only where a helper says so
export function apiClient(transport: Transport) {
  const { rpc, upload, uploadJson } = transport;

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
    expect(res.body.result).toBe(true);
    return { invoiceId, recipient, expiresAt };
  }

  // Posts a consignment with the given content, signing the request with the
  // sender key unless a signature is among the overrides
  async function postConsignment(
    t: Transfer,
    content: string,
    overrides: Record<string, string> = {},
  ) {
    const params: Record<string, string> = {
      invoice_id: t.invoiceId,
      transfer_id: t.transferId,
      sender_transport_endpoint: "rpc://sender.example.com/json-rpc",
      sender_pk: t.sender.pubkeyHex,
      consignment_hash: sha256hex("plaintext " + content),
      batch: "false",
      file_size: String(Buffer.byteLength(content)),
      pow_timestamp: String(nowSecs()),
      pow_nonce: "0",
      ...overrides,
    };
    if (!("signature" in overrides)) {
      params.signature = sign(
        t.sender.privateKey,
        hashUtf8Message(
          params.transfer_id +
            params.consignment_hash +
            sha256hex(content) +
            "consignment",
        ),
      );
    }
    return upload("consignment.post", params, content);
  }

  async function postMedia(
    t: Transfer,
    mediaId: string,
    content: string,
    signer: Keypair = t.sender,
  ) {
    return upload(
      "media.post",
      {
        transfer_id: t.transferId,
        media_id: mediaId,
        file_size: String(Buffer.byteLength(content)),
        signature: sign(
          signer.privateKey,
          hashUtf8Message(
            t.transferId + mediaId + sha256hex(content) + "media",
          ),
        ),
      },
      content,
    );
  }

  async function transferList(
    invoice: Invoice,
    signer: Keypair = invoice.recipient,
  ) {
    const timestamp = String(nowSecs());
    return rpc("transfer.list", {
      invoice_id: invoice.invoiceId,
      timestamp,
      signature: sign(
        signer.privateKey,
        hashUtf8Message(invoice.invoiceId + timestamp),
      ),
    });
  }

  async function transferAction(
    action: "retrieved" | "delete",
    transferId: string,
    signer: Keypair,
    signedAction: string = action,
  ) {
    return rpc(`transfer.${action}`, {
      transfer_id: transferId,
      signature: sign(
        signer.privateKey,
        hashUtf8Message(transferId + signedAction),
      ),
    });
  }

  async function invoiceStatus(invoiceId: string) {
    const res = await rpc("invoice.check", { invoice_ids: [invoiceId] });
    return res.body.result[invoiceId].status;
  }

  // ack.prepare carries the signed TXs in its file, given as an object or as
  // the raw content
  function ackPrepareRaw(
    params: Record<string, unknown>,
    signedTxs: Record<string, string> | string,
  ) {
    const content =
      typeof signedTxs === "string" ? signedTxs : JSON.stringify(signedTxs);
    return uploadJson(
      "ack.prepare",
      { file_size: String(Buffer.byteLength(content)), ...params },
      content,
    );
  }

  function ackPrepareOp(op: AckOperation) {
    return ackPrepareRaw(op.params, op.signedTxs);
  }

  async function ackPrepare(count = 1, expiresInSecs = 3600) {
    const op = ackOperation(count, expiresInSecs);
    const res = await ackPrepareOp(op);
    expect(res.body.result).toBe(true);
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
      signature: sign(op.sender.privateKey, ackGetMessage(ids, timestamp)),
    });
  }

  async function ackClean(op: AckOperation) {
    const ids = op.transfers.map((t) => t.transferId);
    return rpc("ack.clean", {
      transfer_ids: ids,
      signature: sign(op.sender.privateKey, ackCleanMessage(ids)),
    });
  }

  return {
    rpc,
    upload,
    uploadJson,
    prepareInvoice,
    postConsignment,
    postMedia,
    transferList,
    transferAction,
    invoiceStatus,
    ackPrepareRaw,
    ackPrepareOp,
    ackPrepare,
    ackPost,
    ackGet,
    ackClean,
  };
}
