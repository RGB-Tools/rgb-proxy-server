import DatabaseConstructor, { type Database } from "better-sqlite3";
import crypto from "crypto";
import express, { Application, NextFunction, Request, Response } from "express";
import httpContext from "express-http-context";
import fs from "fs";
import {
  createJSONRPCErrorResponse,
  JSONRPCErrorCode,
  JSONRPCErrorException,
  JSONRPCErrorResponse,
  JSONRPCParams,
  JSONRPCRequest,
  JSONRPCResponse,
  JSONRPCServer,
} from "json-rpc-2.0";
import multer, { MulterError, StorageEngine } from "multer";
import { homedir } from "os";
import path from "path";

import {
  AlreadyAcked,
  CannotChange,
  FileTooLarge,
  Invalid,
  InvalidContentSignature,
  InvalidEndpointAuthSignature,
  InvalidProofOfWork,
  InvalidProxyAuthSignature,
  InvoiceExpired,
  InvoiceNotReserved,
  InvoiceQuotaExceeded,
  Missing,
  MissingFile,
  NotFoundConsignment,
  NotFoundMedia,
  OperationExpired,
  OperationNotFound,
  ServerDraining,
  SignedTxTooLarge,
  TooManyTransfers,
  TransferDataRetrieved,
  TransferIdDeleted,
  TransferIdInUse,
  TransferNotFound,
} from "../errors";
import { logger } from "../logger";
import { ProofOfWork, verifyPowSolution } from "../pow";
import { setDir } from "../util";
import { DEFAULT_APP_DATA } from "../vars";
import { APP_VERSION } from "../version";

const PROTOCOL_VERSION = "1.0";

// Ed25519 SPKI DER prefix (12 bytes): wraps a raw 32-byte key into the
// SubjectPublicKeyInfo structure required by crypto.createPublicKey.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const DATABASE_FILE = "app.db";
// Domain separation prefix of the transfer ID derivation
const TRANSFER_ID_PREFIX = "rgb-proxy-server/transfer/v1";
// Default max expiration: 30 days in seconds
const DEFAULT_MAX_EXPIRY_SECS = 2592000;
// Measured as the length of the base64 signed_tx string
const DEFAULT_MAX_SIGNED_TX_SIZE = 153600; // 150 KiB
const DEFAULT_MAX_TRANSFERS = 1000;
const DEFAULT_MAX_UPLOAD_BYTES = 104857600; // 100 MiB
// Default max number of transfers an invoice can be reserved for
const DEFAULT_MAX_QUOTA = 100;
// Default max time the data awaiting retrieval is kept after its expiration:
// 1 day
const DEFAULT_RETENTION_GRACE_SECS = 86400;
// Adaptive proof of work defaults (see src/pow.ts)
const DEFAULT_MAX_POW_DIFFICULTY = 24;
const DEFAULT_POW_RATE_THRESHOLD = 10;
const DEFAULT_POW_RATE_STEP = 2;
const DEFAULT_POW_GLOBAL_THRESHOLD = 1000;
const DEFAULT_POW_GLOBAL_STEP = 50;
const DEFAULT_POW_WINDOW_SECS = 3600; // 1 hour
const DEFAULT_POW_HOLD_SECS = 600; // 10 minutes
// A SHA-256 digest has 256 bits
const POW_DIFFICULTY_LIMIT = 256;
// Max allowed distance from the proxy clock of timestamp and pow_timestamp
const TIMESTAMP_TOLERANCE_SECS = 300;
// Per-transfer allowance for the ack.prepare fields other than the signed TX
const ACK_PREPARE_TRANSFER_OVERHEAD_BYTES = 1024;
const JSON_BODY_BASE_BYTES = 102400; // 100 KiB

let maxExpirySecs: number;
let maxSignedTxSize: number;
let maxTransfers: number;
let maxUploadBytes: number;
let maxQuota: number;
let retentionGraceSecs: number;
let proxyAuthPubkeys: string[] = [];
let pow: ProofOfWork;

// file_size declared by the client, if the field was received before the file
// part (multipart fields are only available in the order they are sent)
function getDeclaredFileSize(req: Request): number | undefined {
  let params = req.body?.params;
  if (isString(params)) {
    try {
      params = JSON.parse(params);
    } catch {
      return undefined;
    }
  }
  const raw = isDictionary(params) ? params["file_size"] : undefined;
  if (!isString(raw) || !/^\d+$/.test(raw)) return undefined;
  const size = parseInt(raw, 10);
  return size.toString() === raw ? size : undefined;
}

// An uploaded file, with the hash of its bytes (blob_hash) computed while it
// was received
interface UploadedFile extends Express.Multer.File {
  blobHash: string;
}

// Disk storage that hashes and counts the bytes as they are received and
// aborts the upload as soon as the declared file_size is exceeded. The params
// must precede the file, so that its declared size is known while it's
// received. If file_size is missing or not valid, the file is drained without
// being stored, as the API method refuses the params before using it.
const storage: StorageEngine = {
  _handleFile(req, file, cb) {
    if (req.body?.params === undefined) {
      file.stream.resume();
      return cb(new Invalid(["file"]));
    }
    const declaredSize = getDeclaredFileSize(req);
    if (declaredSize !== undefined && declaredSize > maxUploadBytes) {
      file.stream.resume();
      return cb(new FileTooLarge());
    }
    if (declaredSize === undefined) {
      file.stream.resume();
      return cb(null, {});
    }
    const filename = crypto.randomBytes(16).toString("hex");
    const finalPath = path.join(tempDir, filename);
    const outStream = fs.createWriteStream(finalPath);
    const hash = crypto.createHash("sha256");
    let received = 0;
    let aborted = false;

    file.stream.on("data", (chunk: Buffer) => {
      if (aborted) return;
      received += chunk.length;
      hash.update(chunk);
      if (received <= declaredSize) return;
      aborted = true;
      file.stream.unpipe(outStream);
      file.stream.resume();
      outStream.destroy();
      fs.unlink(finalPath, () => cb(new Invalid(["file_size"])));
    });
    file.stream.pipe(outStream);
    outStream.on("error", (err) => {
      if (!aborted) cb(err);
    });
    outStream.on("finish", () => {
      const info: Partial<UploadedFile> = {
        destination: tempDir,
        filename,
        path: finalPath,
        size: outStream.bytesWritten,
        blobHash: hash.digest("hex"),
      };
      cb(null, info);
    });
  },
  _removeFile(_req, file, cb) {
    if (!file.path) return cb(null);
    fs.unlink(file.path, cb);
  },
};

let upload: ReturnType<typeof multer>;

let appDir: string;
let db: Database;
let gcTimer: NodeJS.Timeout | undefined;
// Set when draining, see startDraining
let draining = false;
let tempDir: string;
let consignmentDir: string;
let mediaDir: string;

// ---------------------------------------------------------------------------
// DB row interfaces
// ---------------------------------------------------------------------------

interface InvoiceRow {
  invoice_id: string;
  expiration: number;
  recipient_pk: string;
  quota: number;
}

// pending: the transfer data (consignment and media) is available
// retrieved: the transfer data has been deleted via transfer.retrieved
// deleted: the transfer has been deleted via transfer.delete, only its record
//          is kept so that its transfer ID cannot be reused
type TransferStatus = "pending" | "retrieved" | "deleted";

interface TransferRow {
  transfer_id: string;
  invoice_id: string;
  status: TransferStatus;
  sender_transport_endpoint: string;
  sender_pk: string;
  consignment_hash: string;
  batch: number;
  // hash of the uploaded file, kept to recognize identical re-posts
  file_hash: string;
  // name of the stored file, null once the data has been deleted
  filename: string | null;
}

interface MediaRow {
  transfer_id: string;
  media_id: string;
  // hash of the uploaded file, kept to recognize identical re-posts
  file_hash: string;
  // name of the stored file, null once the data has been deleted
  filename: string | null;
}

interface AckOperationRow {
  id: number;
  expiration: number;
  signed_tx_hash: string;
  sender_pk: string;
}

interface AckTransferRow {
  transfer_id: string;
  operation_id: number;
  recipient_pk: string;
  consignment_hash: string;
  // signed TX of the operation, null once deleted (by ack.clean, a NACK or the
  // operation expiring before being released)
  signed_tx: string | null;
  // recipient response: null until posted, 1 for an ACK, 0 for a NACK
  acked: number | null;
  // recipient signature of the response, null until posted
  ack_signature: string | null;
  // Whether ack.get has returned the response, only used to know when a drain
  // can complete (see countPending)
  fetched: number;
}

// ---------------------------------------------------------------------------
// API response interfaces
// ---------------------------------------------------------------------------

interface ServerInfo {
  version: string;
  protocol_version: string;
  uptime: number;
  current_time: string;
  max_expiry_secs: string;
  max_quota: string;
  max_pow_difficulty: string;
  retention_grace_secs: string;
  max_file_size: string;
  max_signed_tx_size: string;
  max_transfers: string;
}

type InvoiceStatus = "unknown" | "available" | "full";

interface InvoiceCheckRes {
  status: InvoiceStatus;
  pow_difficulty: string;
}

interface ConsignmentGetRes {
  consignment: string;
  sender_transport_endpoint: string;
  sender_pk: string;
  consignment_hash: string;
  batch: boolean;
}

interface AckPostRes {
  result: boolean;
  // only on ACK
  sender_pk?: string;
  signed_tx?: string;
  signed_tx_hash?: string;
  expires_at: string;
}

interface AckGetRes {
  acks: Record<string, boolean>;
  signatures: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Helpers – type guards
// ---------------------------------------------------------------------------

function isBoolean(data: unknown): data is boolean {
  return typeof data === "boolean";
}

function isDictionary(data: unknown): data is Record<keyof never, unknown> {
  return typeof data === "object" && !Array.isArray(data) && data !== null;
}

function isString(data: unknown): data is string {
  return typeof data === "string";
}

function isNonEmptyString(data: unknown): data is string {
  return isString(data) && data.length > 0;
}

function isArray(data: unknown): data is unknown[] {
  return Array.isArray(data);
}

function isErrorResponse(
  object: JSONRPCResponse,
): object is JSONRPCErrorResponse {
  return "error" in object;
}

// IDs, hashes and pubkeys are transmitted as lowercase hex
function isHex64(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{64}$/.test(value);
}

// Signatures are transmitted as lowercase hex
function isHex128(value: unknown): value is string {
  return isString(value) && /^[0-9a-f]{128}$/.test(value);
}

// Non-empty standard base64 with padding, as used for all binary blobs
function isBase64(value: unknown): value is string {
  return (
    isNonEmptyString(value) &&
    value.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(value)
  );
}

// The proof of work nonce is chosen by the sender: 1 to 64 printable ASCII
// characters
function isPowNonce(value: unknown): value is string {
  return isString(value) && /^[\x20-\x7e]{1,64}$/.test(value);
}

// ---------------------------------------------------------------------------
// Helpers – logging
// ---------------------------------------------------------------------------

function truncateText(content: string, limit = 16) {
  if (!content) return "";
  if (content.length <= limit) return content;
  return content.slice(0, limit) + "...";
}

// Short form of a value for the logs: strings are truncated and maps are
// summarized by their number of entries
function summarize(value: unknown): unknown {
  if (isString(value)) return truncateText(value);
  if (isArray(value)) return `[${value.map(summarize).join(", ")}]`;
  if (isDictionary(value)) return `{${Object.keys(value).length} entries}`;
  return value;
}

function joinEntries(entries: object) {
  const joined = Object.entries(entries)
    .map(([k, v]) => `${k}: ${summarize(v)}`)
    .join(", ");
  return `<${joined}>`;
}

// ---------------------------------------------------------------------------
// Helpers – crypto
// ---------------------------------------------------------------------------

function verifyEd25519(
  pubkeyHex: string,
  signatureHex: string,
  message: Buffer,
): boolean {
  try {
    const spkiDer = Buffer.concat([
      ED25519_SPKI_PREFIX,
      Buffer.from(pubkeyHex, "hex"),
    ]);
    const keyObject = crypto.createPublicKey({
      key: spkiDer,
      format: "der",
      type: "spki",
    });
    return crypto.verify(
      null,
      message,
      keyObject,
      Buffer.from(signatureHex, "hex"),
    );
  } catch {
    return false;
  }
}

export function parseProxyAuthPubkeys(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(/[,\s]+/)
    .map((pubkey) => pubkey.trim())
    .filter(Boolean);
}

export function verifyAnyEd25519(
  pubkeyHexes: string[],
  signatureHex: string,
  message: Buffer,
): boolean {
  return pubkeyHexes.some((pubkeyHex) =>
    verifyEd25519(pubkeyHex, signatureHex, message),
  );
}

/** SHA-256 of UTF-8 bytes — used as the payload for Ed25519 auth signatures. */
export function hashUtf8Message(data: string): Buffer {
  return crypto.createHash("sha256").update(Buffer.from(data, "utf8")).digest();
}

/** Transfer ID of the transfer to the invoice from the sender pubkey. */
export function deriveTransferId(invoiceId: string, senderPk: string): string {
  return hashUtf8Message(TRANSFER_ID_PREFIX + invoiceId + senderPk).toString(
    "hex",
  );
}

export function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
): number {
  const parsed = parseInt(raw ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function parseNonNegativeInt(
  raw: string | undefined,
  fallback: number,
): number {
  const parsed = parseInt(raw ?? "", 10);
  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

function nowSecs(): number {
  return Math.floor(Date.now() / 1000);
}

// Fractional seconds, for the proof of work difficulty
function powNow(): number {
  return Date.now() / 1000;
}

// ---------------------------------------------------------------------------
// Helpers – parameter extraction
// ---------------------------------------------------------------------------

interface TransferData {
  recipient_pk: string;
  consignment_hash: string;
  signed_tx: string;
}

// Reads and validates the request parameters, collecting every field that
// fails validation so that a single error can report them all.  Getters
// return a placeholder for fields that failed: check() must be called, and
// throws, before any of the values is used.
class ParamReader {
  private readonly params: Record<keyof never, unknown>;
  private readonly missing: string[] = [];
  private readonly invalid: string[] = [];

  constructor(params: Partial<JSONRPCParams> | undefined) {
    this.params = isDictionary(params) ? params : {};
  }

  private addMissing(field: string): void {
    if (!this.missing.includes(field)) this.missing.push(field);
  }

  private addInvalid(field: string): void {
    if (!this.invalid.includes(field)) this.invalid.push(field);
  }

  private tryRead<T>(
    key: string,
    isValid: (value: unknown) => value is T,
  ): T | undefined {
    if (!(key in this.params)) {
      this.addMissing(key);
      return undefined;
    }
    const value = this.params[key];
    if (!isValid(value)) {
      this.addInvalid(key);
      return undefined;
    }
    return value;
  }

  private read<T>(
    key: string,
    isValid: (value: unknown) => value is T,
    placeholder: T,
  ): T {
    return this.tryRead(key, isValid) ?? placeholder;
  }

  // Missing fields take precedence over invalid ones
  check(): void {
    if (this.missing.length > 0) throw new Missing(this.missing);
    if (this.invalid.length > 0) throw new Invalid(this.invalid);
  }

  string(key: string): string {
    return this.read(key, isNonEmptyString, "");
  }

  hex64(key: string): string {
    return this.read(key, isHex64, "");
  }

  hex128(key: string): string {
    return this.read(key, isHex128, "");
  }

  // Required only when proxy auth pubkeys are configured (see checkProxyAuth)
  proxyAuthSignature(): string {
    return proxyAuthPubkeys.length > 0 ? this.hex128("signature") : "";
  }

  base64(key: string): string {
    return this.read(key, isBase64, "");
  }

  boolean(key: string): boolean {
    return this.read(key, isBoolean, false);
  }

  // Like boolean(), also accepting "true" and "false", as multipart form
  // fields arrive as strings
  flag(key: string): boolean {
    if (!(key in this.params)) {
      this.addMissing(key);
      return false;
    }
    const value = this.params[key];
    if (isBoolean(value)) return value;
    if (value === "true") return true;
    if (value === "false") return false;
    this.addInvalid(key);
    return false;
  }

  // Non-negative integer carried as a string
  private intString(key: string): number | undefined {
    const raw = this.string(key);
    if (!raw) return undefined;
    if (!/^\d+$/.test(raw) || parseInt(raw, 10).toString() !== raw) {
      this.addInvalid(key);
      return undefined;
    }
    return parseInt(raw, 10);
  }

  // Invalid both when in the past and when beyond the max allowed expiration
  expiresAt(): number {
    const exp = this.intString("expires_at");
    if (exp === undefined) return 0;
    const now = nowSecs();
    if (exp <= now || exp > now + maxExpirySecs) this.addInvalid("expires_at");
    return exp;
  }

  // Invalid when not within the tolerance from the proxy clock
  timestamp(): string {
    const timestamp = this.intString("timestamp");
    if (timestamp === undefined) return "";
    if (Math.abs(timestamp - nowSecs()) > TIMESTAMP_TOLERANCE_SECS) {
      this.addInvalid("timestamp");
    }
    return String(timestamp);
  }

  fileSize(): number {
    return this.intString("file_size") ?? 0;
  }

  // Optional, defaults to 1; invalid when not within 1 and maxQuota (it is
  // rejected rather than clamped)
  quota(): number {
    if (!("quota" in this.params)) return 1;
    const quota = this.intString("quota");
    if (quota === undefined) return 1;
    if (quota < 1 || quota > maxQuota) this.addInvalid("quota");
    return quota;
  }

  // Only malformed values are invalid here: the distance from the proxy clock
  // is part of the proof of work verification
  powTimestamp(): string {
    const timestamp = this.intString("pow_timestamp");
    return timestamp === undefined ? "" : String(timestamp);
  }

  powNonce(): string {
    return this.read("pow_nonce", isPowNonce, "");
  }

  // Non-empty array of IDs, each element is reported as itemKey if invalid
  private idList(key: string, itemKey: string): string[] {
    const ids = this.tryRead(key, isArray);
    if (ids === undefined) return [];
    if (ids.length === 0) this.addInvalid(key);
    if (!ids.every(isHex64)) this.addInvalid(itemKey);
    return ids as string[];
  }

  invoiceIds(): string[] {
    return this.idList("invoice_ids", "invoice_id");
  }

  // Transfer IDs identify an operation, so they must not be repeated
  transferIds(): string[] {
    const ids = this.idList("transfer_ids", "transfer_id");
    if (new Set(ids).size !== ids.length) this.addInvalid("transfer_ids");
    return ids;
  }

  // Non-empty map from transfer ID to its ack.prepare data
  transferData(): Record<string, TransferData> {
    const result: Record<string, TransferData> = {};
    const td = this.tryRead("transfer_data", isDictionary);
    if (td === undefined) return result;
    const entries = Object.entries(td);
    if (entries.length === 0) this.addInvalid("transfer_data");
    for (const [transferId, entry] of entries) {
      if (!isHex64(transferId)) this.addInvalid("transfer_id");
      if (!isDictionary(entry)) {
        this.addInvalid("transfer_data");
        continue;
      }
      const fields = new ParamReader(entry);
      result[transferId] = {
        recipient_pk: fields.hex64("recipient_pk"),
        consignment_hash: fields.hex64("consignment_hash"),
        signed_tx: fields.base64("signed_tx"),
      };
      fields.missing.forEach((f) => this.addMissing(f));
      fields.invalid.forEach((f) => this.addInvalid(f));
    }
    return result;
  }
}

// Names of the received fields whose values differ from the stored ones
function changedFields(
  stored: Record<string, unknown>,
  received: Record<string, unknown>,
): string[] {
  return Object.keys(received).filter((k) => stored[k] !== received[k]);
}

// Verifies the optional proxy auth signature, required only when proxy auth
// pubkeys are configured
function checkProxyAuth(signature: string, message: string): void {
  if (proxyAuthPubkeys.length === 0) return;
  if (
    !verifyAnyEd25519(proxyAuthPubkeys, signature, hashUtf8Message(message))
  ) {
    throw new InvalidProxyAuthSignature();
  }
}

// ---------------------------------------------------------------------------
// Helpers – uploads
// ---------------------------------------------------------------------------

// Returns the uploaded file once it has been checked against the maximum and
// the declared size, which it must match exactly. The temp file is removed by
// the route once the call returns, unless the method has stored it (see
// storeUpload).
function receivedUpload(
  file: UploadedFile | undefined,
  declaredSize: number,
): UploadedFile {
  if (declaredSize > maxUploadBytes) throw new FileTooLarge();
  if (!file) throw new MissingFile();
  if (file.size !== declaredSize) throw new Invalid(["file_size"]);
  return file;
}

// Moves the uploaded file to its storage dir, named after its hash so that
// identical files are shared, then records it with insert(). If the insert
// fails, the stored file is removed (unless another row references it),
// keeping the filesystem and the DB in sync.
function storeUpload(
  file: UploadedFile,
  table: "transfers" | "transfer_media",
  insert: () => void,
): void {
  const dir = table === "transfers" ? consignmentDir : mediaDir;
  fs.renameSync(file.path, path.join(dir, file.blobHash));
  try {
    insert();
  } catch (e) {
    unlinkIfUnreferenced(table, file.blobHash);
    throw e;
  }
}

// ---------------------------------------------------------------------------
// Helpers – recipient proxy data
// ---------------------------------------------------------------------------

function getInvoice(invoiceId: string): InvoiceRow | undefined {
  return db
    .prepare("SELECT * FROM invoices WHERE invoice_id = ?")
    .get(invoiceId) as InvoiceRow | undefined;
}

function getTransfer(transferId: string): TransferRow | undefined {
  return db
    .prepare("SELECT * FROM transfers WHERE transfer_id = ?")
    .get(transferId) as TransferRow | undefined;
}

function getMedia(transferId: string, mediaId: string): MediaRow | undefined {
  return db
    .prepare(
      "SELECT * FROM transfer_media WHERE transfer_id = ? AND media_id = ?",
    )
    .get(transferId, mediaId) as MediaRow | undefined;
}

// Transfers counting towards the invoice quota (deleted ones free their slot)
function countQuotaTransfers(invoiceId: string): number {
  return (
    db
      .prepare(
        `SELECT COUNT(*) AS n FROM transfers
         WHERE invoice_id = ? AND status != 'deleted'`,
      )
      .get(invoiceId) as { n: number }
  ).n;
}

function getInvoiceStatus(invoiceId: string): InvoiceStatus {
  const invoice = getInvoice(invoiceId);
  if (!invoice) return "unknown";
  return countQuotaTransfers(invoiceId) < invoice.quota ? "available" : "full";
}

// Stored files are named after their hash, so identical files are shared:
// delete one only when no row references it anymore
function unlinkIfUnreferenced(
  table: "transfers" | "transfer_media",
  filename: string,
): void {
  const refs = (
    db
      .prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE filename = ?`)
      .get(filename) as { n: number }
  ).n;
  if (refs > 0) return;
  const dir = table === "transfers" ? consignmentDir : mediaDir;
  try {
    fs.unlinkSync(path.join(dir, filename));
  } catch {}
}

function mediaFilenames(transferIds: string[]): string[] {
  if (transferIds.length === 0) return [];
  const placeholders = transferIds.map(() => "?").join(", ");
  return (
    db
      .prepare(
        `SELECT DISTINCT filename FROM transfer_media
         WHERE transfer_id IN (${placeholders}) AND filename IS NOT NULL`,
      )
      .all(...transferIds) as { filename: string }[]
  ).map((r) => r.filename);
}

// Delete the consignment and media of a transfer, marking it as retrieved
// (metadata kept, so identical re-posts are still recognized) or deleted
// (only the record of its transfer ID kept, so it cannot be reused)
function dropTransferData(
  transfer: TransferRow,
  status: Exclude<TransferStatus, "pending">,
): void {
  const media = mediaFilenames([transfer.transfer_id]);
  db.transaction(() => {
    db.prepare(
      "UPDATE transfers SET status = ?, filename = NULL WHERE transfer_id = ?",
    ).run(status, transfer.transfer_id);
    if (status === "deleted") {
      db.prepare("DELETE FROM transfer_media WHERE transfer_id = ?").run(
        transfer.transfer_id,
      );
    } else {
      db.prepare(
        "UPDATE transfer_media SET filename = NULL WHERE transfer_id = ?",
      ).run(transfer.transfer_id);
    }
  })();
  if (transfer.filename) unlinkIfUnreferenced("transfers", transfer.filename);
  media.forEach((f) => unlinkIfUnreferenced("transfer_media", f));
}

// Delete all the data of an invoice: reservation, transfers (including the
// records of deleted ones), consignments and media
function deleteInvoiceData(invoiceId: string): void {
  const transfers = db
    .prepare("SELECT transfer_id, filename FROM transfers WHERE invoice_id = ?")
    .all(invoiceId) as Pick<TransferRow, "transfer_id" | "filename">[];
  const media = mediaFilenames(transfers.map((t) => t.transfer_id));
  db.transaction(() => {
    db.prepare(
      `DELETE FROM transfer_media WHERE transfer_id IN
         (SELECT transfer_id FROM transfers WHERE invoice_id = ?)`,
    ).run(invoiceId);
    db.prepare("DELETE FROM transfers WHERE invoice_id = ?").run(invoiceId);
    db.prepare("DELETE FROM invoices WHERE invoice_id = ?").run(invoiceId);
  })();
  for (const { filename } of transfers) {
    if (filename) unlinkIfUnreferenced("transfers", filename);
  }
  media.forEach((f) => unlinkIfUnreferenced("transfer_media", f));
  pow.forget(invoiceId);
}

// ---------------------------------------------------------------------------
// Helpers – sender proxy data
// ---------------------------------------------------------------------------

function buildAckMessage(
  transferId: string,
  ack: boolean,
  consignmentHash: string,
): Buffer {
  return hashUtf8Message(
    transferId + (ack ? "true" : "false") + consignmentHash,
  );
}

function getAckTransfer(transferId: string): AckTransferRow | undefined {
  return db
    .prepare("SELECT * FROM ack_transfers WHERE transfer_id = ?")
    .get(transferId) as AckTransferRow | undefined;
}

function getOperationById(operationId: number | bigint): AckOperationRow {
  return db
    .prepare("SELECT * FROM ack_operations WHERE id = ?")
    .get(operationId) as AckOperationRow;
}

// Looks up the operation the transfer IDs belong to, which must be the same
// single one for all of them
function getAckOperation(transferIds: string[]): AckOperationRow {
  const operationIds = new Set(
    transferIds.map((tid) => {
      const row = getAckTransfer(tid);
      if (!row) throw new OperationNotFound();
      return row.operation_id;
    }),
  );
  if (operationIds.size !== 1) throw new OperationNotFound();
  return getOperationById([...operationIds][0]);
}

// Number of transfers of the operation and how many of them have been ACKed
function ackStats(operationId: number): { total: number; acked: number } {
  const stats = db
    .prepare(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN acked = 1 THEN 1 ELSE 0 END) AS acked
       FROM ack_transfers WHERE operation_id = ?`,
    )
    .get(operationId) as { total: number; acked: number | null };
  return { total: stats.total, acked: stats.acked ?? 0 };
}

// The signed TX is released once every transfer of the operation is ACKed
function isReleased(operationId: number): boolean {
  const { total, acked } = ackStats(operationId);
  return total > 0 && acked === total;
}

// Deletes the signed TXs of the operation, returning how many were present
function dropSignedTxs(operationId: number): number {
  return db
    .prepare(
      `UPDATE ack_transfers SET signed_tx = NULL
       WHERE operation_id = ? AND signed_tx IS NOT NULL`,
    )
    .run(operationId).changes;
}

// ---------------------------------------------------------------------------
// JSON-RPC server
// ---------------------------------------------------------------------------

interface ServerParams {
  file: UploadedFile | undefined;
}

const jsonRpcServer: JSONRPCServer<ServerParams> =
  new JSONRPCServer<ServerParams>({
    errorListener: () => {
      /* avoid too verbose error logs */
    },
  });

// The handlers below never await once the request has been received: every
// check and the related writes run in a single synchronous section, so a
// handler cannot interleave with another one (e.g. two consignment.post calls
// filling the last quota slot, or ack.post and ack.clean for the same
// operation).

// server.info
jsonRpcServer.addMethod(
  "server.info",
  async (_jsonRpcParams, _serverParams): Promise<ServerInfo> => {
    return {
      protocol_version: PROTOCOL_VERSION,
      version: APP_VERSION,
      uptime: Math.trunc(process.uptime()),
      current_time: String(nowSecs()),
      max_expiry_secs: String(maxExpirySecs),
      max_quota: String(maxQuota),
      max_pow_difficulty: String(pow.config.maxDifficulty),
      retention_grace_secs: String(retentionGraceSecs),
      max_file_size: String(maxUploadBytes),
      max_signed_tx_size: String(maxSignedTxSize),
      max_transfers: String(maxTransfers),
    };
  },
);

// invoice.prepare
jsonRpcServer.addMethod(
  "invoice.prepare",
  async (jsonRpcParams, _serverParams): Promise<boolean> => {
    const params = new ParamReader(jsonRpcParams);
    const invoiceId = params.hex64("invoice_id");
    const expiresAt = params.expiresAt();
    const recipientPk = params.hex64("recipient_pk");
    const quota = params.quota();
    const signature = params.proxyAuthSignature();
    params.check();

    checkProxyAuth(
      signature,
      invoiceId + String(expiresAt) + recipientPk + String(quota),
    );

    const existing = getInvoice(invoiceId);
    if (existing) {
      const changed = changedFields(
        {
          expires_at: existing.expiration,
          recipient_pk: existing.recipient_pk,
          quota: existing.quota,
        },
        { expires_at: expiresAt, recipient_pk: recipientPk, quota },
      );
      if (changed.length === 0) return false; // idempotent
      throw new CannotChange(changed);
    }

    assertNotDraining();
    db.prepare(
      `INSERT INTO invoices (invoice_id, expiration, recipient_pk, quota)
       VALUES (?, ?, ?, ?)`,
    ).run(invoiceId, expiresAt, recipientPk, quota);
    return true;
  },
);

// invoice.check
jsonRpcServer.addMethod(
  "invoice.check",
  async (
    jsonRpcParams,
    _serverParams,
  ): Promise<Record<string, InvoiceCheckRes>> => {
    const params = new ParamReader(jsonRpcParams);
    const invoiceIds = params.invoiceIds();
    params.check();

    // Read-only: reading the difficulty doesn't count as a call
    const now = powNow();
    const result: Record<string, InvoiceCheckRes> = {};
    for (const invoiceId of invoiceIds) {
      result[invoiceId] = {
        status: getInvoiceStatus(invoiceId),
        pow_difficulty: String(pow.difficulty(invoiceId, now)),
      };
    }
    return result;
  },
);

// consignment.post
//
// Calls are processed in the order required by the protocol:
// 1. missing, then invalid parameters
// 2. an identical re-post returns false, ignoring the proof of work
// 3. while draining, any other call fails
// 4. reserved and not expired invoice, transfer ID derivation, signature,
//    transfer ID not deleted (then changed data of an existing transfer)
// 5. invoice quota
// 6. proof of work, only if the current difficulty is greater than 0
//
// Only the calls creating a transfer count towards the proof of work
// difficulty: they have passed every check, including the proof of work
// itself, so the difficulty cannot be raised by calls that cost nothing.
jsonRpcServer.addMethod(
  "consignment.post",
  async (jsonRpcParams, serverParams): Promise<boolean> => {
    const params = new ParamReader(jsonRpcParams);
    const invoiceId = params.hex64("invoice_id");
    const transferId = params.hex64("transfer_id");
    const senderTransportEndpoint = params.string("sender_transport_endpoint");
    const senderPk = params.hex64("sender_pk");
    const consignmentHash = params.hex64("consignment_hash");
    const batch = params.flag("batch");
    const fileSize = params.fileSize();
    const signature = params.hex128("signature");
    const powTimestamp = params.powTimestamp();
    const powNonce = params.powNonce();
    params.check();
    const file = receivedUpload(serverParams?.file, fileSize);
    const { blobHash } = file;

    // A deleted transfer is only a record that its transfer ID was used
    const existing = getTransfer(transferId);
    const live =
      existing && existing.status !== "deleted" ? existing : undefined;
    const changed = live
      ? changedFields(
          {
            sender_transport_endpoint: live.sender_transport_endpoint,
            sender_pk: live.sender_pk,
            consignment_hash: live.consignment_hash,
            batch: Boolean(live.batch),
            file: live.file_hash,
          },
          {
            sender_transport_endpoint: senderTransportEndpoint,
            sender_pk: senderPk,
            consignment_hash: consignmentHash,
            batch,
            file: blobHash,
          },
        )
      : [];
    if (live && changed.length === 0 && live.invoice_id === invoiceId) {
      return false; // idempotent, also after transfer.retrieved
    }
    assertNotDraining();

    const invoice = getInvoice(invoiceId);
    if (!invoice) throw new InvoiceNotReserved();
    if (invoice.expiration <= nowSecs()) throw new InvoiceExpired();
    if (deriveTransferId(invoiceId, senderPk) !== transferId) {
      throw new Invalid(["transfer_id"]);
    }
    const message = hashUtf8Message(transferId + consignmentHash + blobHash);
    if (!verifyEd25519(senderPk, signature, message)) {
      throw new InvalidEndpointAuthSignature();
    }
    if (existing?.status === "deleted") throw new TransferIdDeleted();
    if (live) throw new CannotChange(changed);

    if (countQuotaTransfers(invoiceId) >= invoice.quota) {
      throw new InvoiceQuotaExceeded();
    }

    const now = powNow();
    const difficulty = pow.difficulty(invoiceId, now);
    if (difficulty > 0) {
      const inWindow =
        Math.abs(parseInt(powTimestamp, 10) - now) <= TIMESTAMP_TOLERANCE_SECS;
      if (
        !inWindow ||
        !verifyPowSolution(transferId, powTimestamp, powNonce, difficulty)
      ) {
        throw new InvalidProofOfWork(difficulty);
      }
    }

    storeUpload(file, "transfers", () =>
      db
        .prepare(
          `INSERT INTO transfers
             (transfer_id, invoice_id, status, sender_transport_endpoint,
              sender_pk, consignment_hash, batch, file_hash, filename)
           VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          transferId,
          invoiceId,
          senderTransportEndpoint,
          senderPk,
          consignmentHash,
          batch ? 1 : 0,
          blobHash,
          blobHash,
        ),
    );
    pow.record(invoiceId, now);
    return true;
  },
);

// consignment.get
jsonRpcServer.addMethod(
  "consignment.get",
  async (jsonRpcParams, _serverParams): Promise<ConsignmentGetRes> => {
    const params = new ParamReader(jsonRpcParams);
    const transferId = params.hex64("transfer_id");
    params.check();

    const row = getTransfer(transferId);
    if (!row || row.status === "deleted") throw new NotFoundConsignment();
    if (row.filename === null) throw new TransferDataRetrieved();
    const fileBuffer = fs.readFileSync(path.join(consignmentDir, row.filename));
    return {
      consignment: fileBuffer.toString("base64"),
      sender_transport_endpoint: row.sender_transport_endpoint,
      sender_pk: row.sender_pk,
      consignment_hash: row.consignment_hash,
      batch: Boolean(row.batch),
    };
  },
);

// media.post
jsonRpcServer.addMethod(
  "media.post",
  async (jsonRpcParams, serverParams): Promise<boolean> => {
    const params = new ParamReader(jsonRpcParams);
    const transferId = params.hex64("transfer_id");
    const mediaId = params.hex64("media_id");
    const fileSize = params.fileSize();
    const signature = params.hex128("signature");
    params.check();
    const file = receivedUpload(serverParams?.file, fileSize);
    const { blobHash } = file;

    const transfer = getTransfer(transferId);
    if (!transfer || transfer.status === "deleted") {
      throw new TransferNotFound();
    }

    const existing = getMedia(transferId, mediaId);
    if (existing?.file_hash === blobHash) {
      return false; // idempotent, also after transfer.retrieved
    }

    const message = hashUtf8Message(transferId + mediaId + blobHash);
    if (!verifyEd25519(transfer.sender_pk, signature, message)) {
      throw new InvalidEndpointAuthSignature();
    }
    if (existing) throw new CannotChange(["file"]);
    // New media would never be retrievable
    if (transfer.status === "retrieved") throw new TransferDataRetrieved();

    storeUpload(file, "transfer_media", () =>
      db
        .prepare(
          `INSERT INTO transfer_media (transfer_id, media_id, file_hash, filename)
           VALUES (?, ?, ?, ?)`,
        )
        .run(transferId, mediaId, blobHash, blobHash),
    );
    return true;
  },
);

// media.get
jsonRpcServer.addMethod(
  "media.get",
  async (jsonRpcParams, _serverParams): Promise<string> => {
    const params = new ParamReader(jsonRpcParams);
    const transferId = params.hex64("transfer_id");
    const mediaId = params.hex64("media_id");
    params.check();

    const row = getMedia(transferId, mediaId);
    if (!row) throw new NotFoundMedia();
    if (row.filename === null) throw new TransferDataRetrieved();
    const fileBuffer = fs.readFileSync(path.join(mediaDir, row.filename));
    return fileBuffer.toString("base64");
  },
);

// transfer.list
jsonRpcServer.addMethod(
  "transfer.list",
  async (
    jsonRpcParams,
    _serverParams,
  ): Promise<Record<string, Exclude<TransferStatus, "deleted">>> => {
    const params = new ParamReader(jsonRpcParams);
    const invoiceId = params.hex64("invoice_id");
    const signature = params.hex128("signature");
    const timestamp = params.timestamp();
    params.check();

    // Checked before the signature, as the pubkey is only known for reserved
    // invoices
    const invoice = getInvoice(invoiceId);
    if (!invoice) throw new InvoiceNotReserved();
    const message = hashUtf8Message(invoiceId + timestamp);
    if (!verifyEd25519(invoice.recipient_pk, signature, message)) {
      throw new InvalidEndpointAuthSignature();
    }

    const rows = db
      .prepare(
        `SELECT transfer_id, status FROM transfers
         WHERE invoice_id = ? AND status != 'deleted'`,
      )
      .all(invoiceId) as Pick<TransferRow, "transfer_id" | "status">[];
    const result: Record<string, Exclude<TransferStatus, "deleted">> = {};
    for (const row of rows) {
      result[row.transfer_id] = row.status as Exclude<
        TransferStatus,
        "deleted"
      >;
    }
    return result;
  },
);

// Reads the parameters of transfer.retrieved and transfer.delete, returning
// the transfer once the signature by the invoice pubkey over transfer_id
// followed by the action has been verified
function authenticatedTransfer(
  jsonRpcParams: Partial<JSONRPCParams> | undefined,
  action: "retrieved" | "delete",
): TransferRow {
  const params = new ParamReader(jsonRpcParams);
  const transferId = params.hex64("transfer_id");
  const signature = params.hex128("signature");
  params.check();

  // Checked before the signature, as the pubkey is only known for the
  // invoice of an existing transfer
  const transfer = getTransfer(transferId);
  if (!transfer) throw new TransferNotFound();
  const invoice = getInvoice(transfer.invoice_id) as InvoiceRow;
  const message = hashUtf8Message(transferId + action);
  if (!verifyEd25519(invoice.recipient_pk, signature, message)) {
    throw new InvalidEndpointAuthSignature();
  }
  return transfer;
}

// transfer.retrieved
jsonRpcServer.addMethod(
  "transfer.retrieved",
  async (jsonRpcParams, _serverParams): Promise<boolean> => {
    const transfer = authenticatedTransfer(jsonRpcParams, "retrieved");
    if (transfer.status !== "pending") return false; // idempotent
    dropTransferData(transfer, "retrieved");
    return true;
  },
);

// transfer.delete
jsonRpcServer.addMethod(
  "transfer.delete",
  async (jsonRpcParams, _serverParams): Promise<boolean> => {
    const transfer = authenticatedTransfer(jsonRpcParams, "delete");
    if (transfer.status === "deleted") return false; // idempotent
    dropTransferData(transfer, "deleted");
    return true;
  },
);

// ack.prepare
jsonRpcServer.addMethod(
  "ack.prepare",
  async (jsonRpcParams, _serverParams): Promise<boolean> => {
    const params = new ParamReader(jsonRpcParams);
    const transferData = params.transferData();
    const expiresAt = params.expiresAt();
    const signedTxHash = params.hex64("signed_tx_hash");
    const senderPk = params.hex64("sender_pk");
    const signature = params.proxyAuthSignature();
    params.check();

    const transferIds = Object.keys(transferData).sort();
    if (transferIds.length > maxTransfers) {
      throw new TooManyTransfers();
    }
    for (const td of Object.values(transferData)) {
      if (td.signed_tx.length > maxSignedTxSize) {
        throw new SignedTxTooLarge();
      }
    }

    checkProxyAuth(
      signature,
      senderPk +
        String(expiresAt) +
        signedTxHash +
        transferIds
          .map((tid) => {
            const td = transferData[tid];
            return tid + td.recipient_pk + td.consignment_hash;
          })
          .join(""),
    );

    return db.transaction((): boolean => {
      // Check existing registrations
      const existingRows = transferIds
        .map(getAckTransfer)
        .filter((r): r is AckTransferRow => r !== undefined);

      if (existingRows.length === 0) {
        // All new: insert the operation and all its transfers
        assertNotDraining();
        const opResult = db
          .prepare(
            `INSERT INTO ack_operations (expiration, signed_tx_hash, sender_pk)
             VALUES (?, ?, ?)`,
          )
          .run(expiresAt, signedTxHash, senderPk);
        const operationId = opResult.lastInsertRowid;
        const insertTransfer = db.prepare(
          `INSERT INTO ack_transfers
             (transfer_id, operation_id, recipient_pk, consignment_hash,
              signed_tx)
           VALUES (?, ?, ?, ?, ?)`,
        );
        for (const tid of transferIds) {
          const td = transferData[tid];
          insertTransfer.run(
            tid,
            operationId,
            td.recipient_pk,
            td.consignment_hash,
            td.signed_tx,
          );
        }
        return true;
      }

      // Some or all already exist: they must all belong to the same operation
      const operationIds = new Set(existingRows.map((r) => r.operation_id));
      if (operationIds.size > 1 || existingRows.length !== transferIds.length) {
        throw new TransferIdInUse();
      }
      const operationId = existingRows[0].operation_id;

      // The request must cover the full transfer set of the operation, not a
      // subset
      if (ackStats(operationId).total !== transferIds.length) {
        throw new TransferIdInUse();
      }
      const op = getOperationById(operationId);

      const changed = new Set(
        changedFields(
          {
            expires_at: op.expiration,
            signed_tx_hash: op.signed_tx_hash,
            sender_pk: op.sender_pk,
          },
          {
            expires_at: expiresAt,
            signed_tx_hash: signedTxHash,
            sender_pk: senderPk,
          },
        ),
      );
      for (const row of existingRows) {
        const td = transferData[row.transfer_id];
        changedFields(
          {
            recipient_pk: row.recipient_pk,
            consignment_hash: row.consignment_hash,
            signed_tx: row.signed_tx,
          },
          { ...td },
        ).forEach((f) => changed.add(f));
      }
      if (changed.size > 0) throw new CannotChange([...changed]);

      return false; // idempotent
    })();
  },
);

// ack.post
jsonRpcServer.addMethod(
  "ack.post",
  async (jsonRpcParams, _serverParams): Promise<AckPostRes> => {
    const params = new ParamReader(jsonRpcParams);
    const transferId = params.hex64("transfer_id");
    const ack = params.boolean("ack");
    const signature = params.hex128("signature");
    params.check();

    // The checks and the writes run in a single synchronous transaction, with
    // no await in between, so ack.post and ack.clean calls for the same
    // operation are atomic with respect to each other: either ack.clean
    // removes the signed TXs before the last ACK is registered, so that no TX
    // is released, or the last ACK is registered first and ack.clean is
    // refused.
    return db.transaction((): AckPostRes => {
      const row = getAckTransfer(transferId);
      if (!row) throw new OperationNotFound();
      const op = getOperationById(row.operation_id);
      const signatureValid = () =>
        verifyEd25519(
          row.recipient_pk,
          signature,
          buildAckMessage(transferId, ack, row.consignment_hash),
        );

      // Idempotency / cannot-change check (allowed even after expiration)
      if (row.acked !== null) {
        const existingAck = Boolean(row.acked);
        if (existingAck === ack && row.ack_signature === signature) {
          const res = buildAckPostRes(false, transferId, ack, op);
          // A recipient still waiting on the rest of a batch gets no
          // signed_tx back. Once the operation has expired the TX can never
          // be released, so surface the expiration instead of letting the
          // recipient poll forever. A recipient whose TX was already released
          // can still re-fetch it past the expiration (res.signed_tx is set).
          // A NACK never releases anything, so it stays idempotent past the
          // expiration. The operation data, including a released TX, is kept
          // until the retention grace after the expiration has passed (see
          // runGC).
          if (
            ack &&
            res.signed_tx === undefined &&
            op.expiration <= nowSecs()
          ) {
            throw new OperationExpired();
          }
          return res;
        }
        // Verified first, so that only the recipient can learn the stored
        // response from the error
        if (!signatureValid()) throw new InvalidContentSignature();
        throw new CannotChange(
          existingAck !== ack ? ["ack", "signature"] : ["signature"],
        );
      }

      if (op.expiration <= nowSecs()) throw new OperationExpired();
      if (!signatureValid()) throw new InvalidContentSignature();

      // Store ack + signature. A NACK makes the operation unreleasable, so
      // drop all signed TX copies immediately.
      db.prepare(
        `UPDATE ack_transfers SET acked = ?, ack_signature = ?
         WHERE transfer_id = ?`,
      ).run(ack ? 1 : 0, signature, transferId);
      if (!ack) dropSignedTxs(op.id);

      return buildAckPostRes(true, transferId, ack, op);
    })();
  },
);

function buildAckPostRes(
  isNew: boolean,
  transferId: string,
  ack: boolean,
  op: AckOperationRow,
): AckPostRes {
  const expiresAt = String(op.expiration);
  if (!ack) {
    return { result: isNew, expires_at: expiresAt };
  }

  // All recipients have acked: return the caller's own signed_tx
  const signedTx = isReleased(op.id)
    ? getAckTransfer(transferId)?.signed_tx
    : null;
  if (signedTx) {
    return {
      result: isNew,
      sender_pk: op.sender_pk,
      signed_tx: signedTx,
      signed_tx_hash: op.signed_tx_hash,
      expires_at: expiresAt,
    };
  }

  // Valid ACK but TX not (yet) released: batch still pending, or TX removed
  return {
    result: isNew,
    sender_pk: op.sender_pk,
    signed_tx_hash: op.signed_tx_hash,
    expires_at: expiresAt,
  };
}

// ack.get
jsonRpcServer.addMethod(
  "ack.get",
  async (jsonRpcParams, _serverParams): Promise<AckGetRes> => {
    const params = new ParamReader(jsonRpcParams);
    const transferIds = params.transferIds();
    const signature = params.hex128("signature");
    const timestamp = params.timestamp();
    params.check();

    const op = getAckOperation(transferIds);

    const sortedIds = [...transferIds].sort();
    const authMessage = hashUtf8Message(sortedIds.join("") + timestamp);
    if (!verifyEd25519(op.sender_pk, signature, authMessage)) {
      throw new InvalidEndpointAuthSignature();
    }

    const allRows = db
      .prepare(
        `SELECT transfer_id, acked, ack_signature FROM ack_transfers
         WHERE operation_id = ?`,
      )
      .all(op.id) as Pick<
      AckTransferRow,
      "transfer_id" | "acked" | "ack_signature"
    >[];

    const requestedIds = new Set(transferIds);
    // Transfers that have not been responded to yet are left out of both maps
    const acks: Record<string, boolean> = {};
    const signatures: Record<string, string> = {};
    for (const r of allRows) {
      if (!requestedIds.has(r.transfer_id)) continue;
      if (r.acked === null || r.ack_signature === null) continue;
      acks[r.transfer_id] = Boolean(r.acked);
      signatures[r.transfer_id] = r.ack_signature;
    }

    // Remember which responses have been retrieved, so that a drain can wait
    // for the sender to get them (see countPending)
    const markFetched = db.prepare(
      "UPDATE ack_transfers SET fetched = 1 WHERE transfer_id = ?",
    );
    db.transaction(() => {
      for (const tid of Object.keys(acks)) markFetched.run(tid);
    })();

    // Calling ack.get doesn't trigger the deletion of the operation data,
    // which is kept until the retention grace after the expiration has passed
    // (see runGC), as recipients may still need to retrieve a released signed
    // TX via ack.post
    return { acks, signatures };
  },
);

// ack.clean
jsonRpcServer.addMethod(
  "ack.clean",
  async (jsonRpcParams, _serverParams): Promise<boolean> => {
    const params = new ParamReader(jsonRpcParams);
    const transferIds = params.transferIds().sort();
    const signature = params.hex128("signature");
    params.check();

    // The checks and the writes run in a single synchronous transaction, with
    // no await in between, so ack.clean and ack.post calls for the same
    // operation are atomic with respect to each other (see ack.post)
    return db.transaction((): boolean => {
      const op = getAckOperation(transferIds);

      // All registered transfer IDs for this operation must be provided
      // (transferIds() rejects duplicates)
      if (ackStats(op.id).total !== transferIds.length) {
        throw new OperationNotFound();
      }

      // Canonical message: SHA-256 of the sorted transfer IDs concatenated
      // (e.g. "tidAtidB")
      const message = hashUtf8Message(transferIds.join(""));
      if (!verifyEd25519(op.sender_pk, signature, message)) {
        throw new InvalidEndpointAuthSignature();
      }

      // Refused once every transfer has been ACKed, as the signed TX has been
      // released. Allowed after partial responses, while after a NACK there
      // is no signed TX left to remove.
      if (isReleased(op.id)) throw new AlreadyAcked();

      return dropSignedTxs(op.id) > 0;
    })();
  },
);

// ---------------------------------------------------------------------------
// GC
// ---------------------------------------------------------------------------

// Data retention policy:
// - the data of an invoice (reservation, transfers including the records of
//   deleted ones, consignments, media) is never deleted before the invoice
//   expiration; after it, it is deleted once no pending transfer (neither
//   retrieved nor deleted) is left or, at the latest, once the retention grace
//   has also passed
// - the signed TXs of an operation that have not been released (not all the
//   transfers have been ACKed, or at least one has been NACKed) are deleted at
//   the operation expiration, as they never will be; everything else (the
//   operation record, the ACK values and signatures and the released signed
//   TXs) is kept until the retention grace after the expiration has passed,
//   regardless of ack.get calls, so that the sender can retrieve the proofs of
//   acknowledgement and recipients can still retrieve a released TX by posting
//   their ACK again
export function runGC(now = nowSecs()): void {
  // Recipient proxy
  const expiredInvoices = db
    .prepare(
      "SELECT invoice_id, expiration FROM invoices WHERE expiration <= ?",
    )
    .all(now) as Pick<InvoiceRow, "invoice_id" | "expiration">[];
  for (const { invoice_id, expiration } of expiredInvoices) {
    const pending = (
      db
        .prepare(
          `SELECT COUNT(*) AS n FROM transfers
           WHERE invoice_id = ? AND status = 'pending'`,
        )
        .get(invoice_id) as { n: number }
    ).n;
    if (pending > 0 && now < expiration + retentionGraceSecs) continue;
    deleteInvoiceData(invoice_id);
  }
  pow.prune(now);

  // Sender proxy
  const expiredOps = db
    .prepare("SELECT id, expiration FROM ack_operations WHERE expiration <= ?")
    .all(now) as Pick<AckOperationRow, "id" | "expiration">[];
  for (const { id, expiration } of expiredOps) {
    if (now < expiration + retentionGraceSecs) {
      // Within the retention grace: keep the operation data, but drop the
      // signed TXs if they have not been released, as they never will be
      if (!isReleased(id)) dropSignedTxs(id);
      continue;
    }

    db.transaction(() => {
      db.prepare("DELETE FROM ack_transfers WHERE operation_id = ?").run(id);
      db.prepare("DELETE FROM ack_operations WHERE id = ?").run(id);
    })();
  }
}

// Start draining: calls that would start a new transfer (invoice.prepare,
// consignment.post and ack.prepare, unless they repeat an already accepted
// call) fail with ServerDraining, while the ones completing pending transfers
// keep working
export const startDraining = (): void => {
  draining = true;
};

const assertNotDraining = (): void => {
  if (draining) throw new ServerDraining();
};

// Number of pending items a drain has to wait for: transfers neither retrieved
// nor deleted (the recipient still has to act on them), and ack operations
// that either can still be answered (not expired, with transfers still
// unanswered) or have responses, ACKs and NACKs alike, that the sender has not
// retrieved with ack.get yet. Operations are removed by runGC after their
// retention grace, which bounds the wait
export function countPending(now = nowSecs()): number {
  const transfers = (
    db
      .prepare("SELECT COUNT(*) AS n FROM transfers WHERE status = 'pending'")
      .get() as { n: number }
  ).n;
  const operations = (
    db
      .prepare(
        `SELECT COUNT(*) AS n FROM ack_operations o
         WHERE EXISTS (
           SELECT 1 FROM ack_transfers t
           WHERE t.operation_id = o.id
             AND ((t.acked IS NULL AND o.expiration > ?)
                  OR (t.acked IS NOT NULL AND t.fetched = 0)))`,
      )
      .get(now) as { n: number }
  ).n;
  return transfers + operations;
}

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------

export const loadApiEndpoints = (app: Application): void => {
  // Checked first, as a misconfigured pubkey would make every authenticated
  // call fail
  const pubkeys = parseProxyAuthPubkeys(
    process.env.PROXY_AUTH_PUBKEYS ?? process.env.PROXY_AUTH_PUBKEY,
  );
  const invalidPubkeys = pubkeys.filter((pk) => !isHex64(pk));
  if (invalidPubkeys.length > 0) {
    throw new Error(
      `Invalid PROXY_AUTH_PUBKEYS (expected 64 lowercase hex characters): ` +
        invalidPubkeys.join(", "),
    );
  }
  proxyAuthPubkeys = pubkeys;

  appDir = process.env.APP_DATA || path.join(homedir(), DEFAULT_APP_DATA);
  setDir(appDir);
  tempDir = path.join(appDir, "tmp");
  consignmentDir = path.join(appDir, "consignments");
  mediaDir = path.join(appDir, "media");
  setDir(tempDir);
  setDir(consignmentDir);
  setDir(mediaDir);

  maxExpirySecs = parsePositiveInt(
    process.env.MAX_EXPIRY_SECS,
    DEFAULT_MAX_EXPIRY_SECS,
  );
  maxSignedTxSize = parsePositiveInt(
    process.env.MAX_SIGNED_TX_SIZE,
    DEFAULT_MAX_SIGNED_TX_SIZE,
  );
  maxTransfers = parsePositiveInt(
    process.env.MAX_TRANSFERS,
    DEFAULT_MAX_TRANSFERS,
  );
  maxUploadBytes = parsePositiveInt(
    process.env.MAX_UPLOAD_BYTES,
    DEFAULT_MAX_UPLOAD_BYTES,
  );
  maxQuota = parsePositiveInt(process.env.MAX_QUOTA, DEFAULT_MAX_QUOTA);
  retentionGraceSecs = parseNonNegativeInt(
    process.env.RETENTION_GRACE_SECS,
    DEFAULT_RETENTION_GRACE_SECS,
  );

  pow = new ProofOfWork({
    maxDifficulty: Math.min(
      POW_DIFFICULTY_LIMIT,
      parseNonNegativeInt(
        process.env.MAX_POW_DIFFICULTY,
        DEFAULT_MAX_POW_DIFFICULTY,
      ),
    ),
    rateThreshold: parsePositiveInt(
      process.env.POW_RATE_THRESHOLD,
      DEFAULT_POW_RATE_THRESHOLD,
    ),
    rateStep: parsePositiveInt(
      process.env.POW_RATE_STEP,
      DEFAULT_POW_RATE_STEP,
    ),
    globalThreshold: parsePositiveInt(
      process.env.POW_GLOBAL_THRESHOLD,
      DEFAULT_POW_GLOBAL_THRESHOLD,
    ),
    globalStep: parsePositiveInt(
      process.env.POW_GLOBAL_STEP,
      DEFAULT_POW_GLOBAL_STEP,
    ),
    windowSecs: parsePositiveInt(
      process.env.POW_WINDOW_SECS,
      DEFAULT_POW_WINDOW_SECS,
    ),
    holdSecs: parseNonNegativeInt(
      process.env.POW_HOLD_SECS,
      DEFAULT_POW_HOLD_SECS,
    ),
  });

  upload = multer({
    storage,
    limits: { fileSize: maxUploadBytes },
  });

  db = new DatabaseConstructor(path.join(appDir, DATABASE_FILE), {});
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  // Recipient proxy tables
  db.prepare(
    `CREATE TABLE IF NOT EXISTS invoices (
       invoice_id   TEXT PRIMARY KEY,
       expiration   INTEGER NOT NULL,
       recipient_pk TEXT NOT NULL,
       quota        INTEGER NOT NULL
     )`,
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS transfers (
       transfer_id                TEXT PRIMARY KEY,
       invoice_id                 TEXT NOT NULL
                                  REFERENCES invoices(invoice_id),
       status                     TEXT NOT NULL,
       sender_transport_endpoint  TEXT NOT NULL,
       sender_pk                  TEXT NOT NULL,
       consignment_hash           TEXT NOT NULL,
       batch                      INTEGER NOT NULL,
       file_hash                  TEXT NOT NULL,
       filename                   TEXT
     )`,
  ).run();
  db.prepare(
    "CREATE INDEX IF NOT EXISTS transfers_invoice_id ON transfers(invoice_id)",
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS transfer_media (
       transfer_id TEXT NOT NULL REFERENCES transfers(transfer_id),
       media_id    TEXT NOT NULL,
       file_hash   TEXT NOT NULL,
       filename    TEXT,
       PRIMARY KEY (transfer_id, media_id)
     )`,
  ).run();

  // Sender proxy tables
  db.prepare(
    `CREATE TABLE IF NOT EXISTS ack_operations (
       id             INTEGER PRIMARY KEY AUTOINCREMENT,
       expiration     INTEGER NOT NULL,
       signed_tx_hash TEXT NOT NULL,
       sender_pk      TEXT NOT NULL
     )`,
  ).run();

  db.prepare(
    `CREATE TABLE IF NOT EXISTS ack_transfers (
       transfer_id      TEXT PRIMARY KEY,
       operation_id     INTEGER NOT NULL REFERENCES ack_operations(id),
       recipient_pk     TEXT NOT NULL,
       consignment_hash TEXT NOT NULL,
       signed_tx        TEXT,
       acked            INTEGER,
       ack_signature    TEXT,
       fetched          INTEGER NOT NULL DEFAULT 0
     )`,
  ).run();

  // Run GC immediately on startup to clear any data that expired while the
  // server was down, then keep running it every 60 seconds.
  // .unref() prevents the timer from keeping the process alive when nothing
  // else is running (e.g. in tests). The handle is kept so that
  // closeApiEndpoints can stop the timer on shutdown.
  runGC();
  gcTimer = setInterval(runGC, 60_000);
  gcTimer.unref();

  // The largest legitimate JSON body is an ack.prepare call carrying
  // maxTransfers signed TXs of maxSignedTxSize each; bigger bodies are aborted
  // while being received
  const maxJsonBodyBytes =
    JSON_BODY_BASE_BYTES +
    maxTransfers * (maxSignedTxSize + ACK_PREPARE_TRANSFER_OVERHEAD_BYTES);

  // Report uploads refused while being received (e.g. due to their size) as
  // JSON-RPC errors
  const uploadFile = (req: Request, res: Response, next: NextFunction) => {
    upload.single("file")(req, res, (err: unknown) => {
      let error: JSONRPCErrorException;
      if (err instanceof JSONRPCErrorException) {
        error = err;
      } else if (err instanceof MulterError && err.code === "LIMIT_FILE_SIZE") {
        error = new FileTooLarge();
      } else {
        return next(err);
      }
      httpContext.set("apiMethod", req.body?.method);
      httpContext.set("clientID", req.body?.id);
      logger.info("", { req });
      sendResponse(
        res,
        createJSONRPCErrorResponse(
          req.body?.id ?? null,
          error.code,
          error.message,
          error.data,
        ),
      );
    });
  };

  app.post(
    "/json-rpc",
    express.json({ limit: maxJsonBodyBytes }),
    uploadFile,
    async (req: Request, res: Response) => {
      const file = req.file as UploadedFile | undefined;
      let response: Awaited<ReturnType<typeof handleRequest>>;
      try {
        response = await handleRequest(req, file);
      } catch (e) {
        logger.error(`Unexpected error: ${e}`);
        response = internalErrorResponse();
      }
      // Uploads are moved out of the temp dir once stored, any other one is
      // removed before responding
      if (file?.path) fs.rmSync(file.path, { force: true });
      sendResponse(res, response);
    },
  );

  // Errors raised before the request reaches the JSON-RPC server (e.g. a body
  // that is not valid JSON) are reported as JSON-RPC errors too
  app.use(
    "/json-rpc",
    (err: unknown, req: Request, res: Response, _next: NextFunction) => {
      logger.info("", { req });
      if (isDictionary(err) && err.type === "entity.parse.failed") {
        return sendResponse(res, parseErrorResponse());
      }
      // Only an ack.prepare call carrying too big signed TXs can legitimately
      // exceed the body limit
      if (isDictionary(err) && err.type === "entity.too.large") {
        const error = new SignedTxTooLarge();
        return sendResponse(
          res,
          createJSONRPCErrorResponse(null, error.code, error.message),
        );
      }
      logger.error(`Unexpected error: ${err}`);
      sendResponse(res, internalErrorResponse());
    },
  );
};

// Release the resources held by the API: stop the GC and close the database
// (checkpointing the WAL). Safe to call more than once
export const closeApiEndpoints = () => {
  clearInterval(gcTimer);
  gcTimer = undefined;
  if (db?.open) db.close();
};

function parseErrorResponse(): JSONRPCErrorResponse {
  return createJSONRPCErrorResponse(
    null,
    JSONRPCErrorCode.ParseError,
    "Parse error",
  );
}

function internalErrorResponse(): JSONRPCErrorResponse {
  return createJSONRPCErrorResponse(
    null,
    JSONRPCErrorCode.InternalError,
    "Internal error",
  );
}

// Passes the request to the JSON-RPC server, once the params of a multipart
// request (sent as a JSON-encoded form field) have been decoded
async function handleRequest(
  req: Request,
  file: UploadedFile | undefined,
): Promise<JSONRPCResponse | JSONRPCResponse[] | null> {
  const body: unknown = req.body;
  if (isArray(body)) {
    logger.info("", { req });
    return jsonRpcServer.receive(body as JSONRPCRequest[], { file });
  }
  if (!isDictionary(body)) {
    logger.info("", { req });
    return createJSONRPCErrorResponse(
      null,
      JSONRPCErrorCode.InvalidRequest,
      "Invalid Request",
    );
  }
  httpContext.set("apiMethod", body.method);
  httpContext.set("clientID", body.id);
  if (isString(body.params)) {
    try {
      body.params = JSON.parse(body.params);
    } catch {
      logger.info("", { req });
      return parseErrorResponse();
    }
  }
  if (isDictionary(body.params)) {
    httpContext.set("reqParams", joinEntries(body.params));
  }
  logger.info("", { req });
  return jsonRpcServer.receive(body as unknown as JSONRPCRequest, { file });
}

// Sends the response, setting its summary for the logs
function sendResponse(
  res: Response,
  response: JSONRPCResponse | JSONRPCResponse[] | null,
): void {
  if (!response) {
    res.sendStatus(204);
    return;
  }
  httpContext.set("response", describeResponse(response));
  res.json(response);
}

function describeResponse(
  response: JSONRPCResponse | JSONRPCResponse[],
): string {
  if (isArray(response)) return `batch of ${response.length}`;
  if (isErrorResponse(response)) {
    return (
      `err <code: ${response.error.code}, ` +
      `message: ${response.error.message}>`
    );
  }
  const result = response.result;
  return isDictionary(result)
    ? `res ${joinEntries(result)}`
    : `res <${summarize(result)}>`;
}
