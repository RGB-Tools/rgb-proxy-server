import express from "express";

import app from "../src/app";
import { hashUtf8Message, loadApiEndpoints } from "../src/controllers/api";
import {
  apiClient,
  appTransport,
  b64,
  futureExpiresAt,
  generateKeypair,
  randomId,
  sha256hex,
  sign,
  startApiApp,
} from "./helpers";

// PROXY_AUTH_PUBKEYS is read once, inside loadApiEndpoints, into a module-level
// variable - it must be set before that call. Jest gives this file its own
// isolated module registry, so this doesn't affect the other suites.
const allowed = generateKeypair();
const otherAllowed = generateKeypair();
startApiApp("temp-proxy-auth-", {
  PROXY_AUTH_PUBKEYS: `${allowed.pubkeyHex}, ${otherAllowed.pubkeyHex}`,
});

const { rpc } = apiClient(appTransport(app));

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
