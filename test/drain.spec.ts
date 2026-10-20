import app from "../src/app";
import { countPending, startDraining } from "../src/controllers/api";
import {
  ackOperation,
  apiClient,
  appTransport,
  invoiceIdOf,
  newTransfer,
  nowSecs,
  randomId,
  startApiApp,
} from "./helpers";

// Draining can't be undone, so this suite has its own module registry and
// the "drain mode" tests must stay after the ones needing a non draining
// server

startApiApp("temp-drain-", {
  // The proof of work stays disabled, see pow-http.spec.ts for it
  POW_RATE_THRESHOLD: "1000000",
  POW_GLOBAL_THRESHOLD: "1000000",
});

const {
  rpc,
  ackPrepareOp,
  prepareInvoice,
  postConsignment,
  postMedia,
  transferList,
  transferAction,
  invoiceStatus,
  ackPrepare,
  ackPost,
  ackGet,
} = apiClient(appTransport(app));

describe("countPending", () => {
  it("counts transfers until they are retrieved or deleted", async () => {
    const before = countPending();
    const invoice = await prepareInvoice("2");
    expect(countPending()).toBe(before);

    const t1 = newTransfer(invoice.invoiceId);
    const t2 = newTransfer(invoice.invoiceId);
    await postConsignment(t1, "one");
    await postConsignment(t2, "two");
    expect(countPending()).toBe(before + 2);

    await transferAction("retrieved", t1.transferId, invoice.recipient);
    expect(countPending()).toBe(before + 1);
    await transferAction("delete", t2.transferId, invoice.recipient);
    expect(countPending()).toBe(before);
  });

  it("counts ack operations until answered and fetched, or expired", async () => {
    const before = countPending();

    const acked = await ackPrepare(2);
    expect(countPending()).toBe(before + 1);
    await ackPost(acked.transfers[0], true);
    await ackPost(acked.transfers[1], true);
    // Answered, but the sender has not retrieved the responses yet
    expect(countPending()).toBe(before + 1);
    await ackGet(acked, [acked.transfers[0].transferId]);
    expect(countPending()).toBe(before + 1);
    await ackGet(acked);
    expect(countPending()).toBe(before);

    // NACKs have to be retrieved too
    const nacked = await ackPrepare(2);
    await ackPost(nacked.transfers[0], false);
    await ackPost(nacked.transfers[1], false);
    expect(countPending()).toBe(before + 1);
    await ackGet(nacked);
    expect(countPending()).toBe(before);

    // An unanswered operation is pending until it expires
    await ackPrepare(1);
    expect(countPending(nowSecs() + 3599)).toBe(
      countPending(nowSecs() + 3601) + 1,
    );
  });
});

describe("drain mode", () => {
  it("refuses new transfers and keeps completing pending ones", async () => {
    const invoice = await prepareInvoice();
    const transfer = newTransfer(invoice.invoiceId);
    expect((await postConsignment(transfer, "pending")).body.result).toBe(true);
    const op = await ackPrepare(2);
    const pending = countPending();

    startDraining();

    const draining = -115;
    const invoiceParams = {
      invoice_id: invoice.invoiceId,
      expires_at: invoice.expiresAt,
      recipient_pk: invoice.recipient.pubkeyHex,
    };

    // New calls starting a transfer fail...
    const newInvoice = await rpc("invoice.prepare", {
      ...invoiceParams,
      invoice_id: invoiceIdOf(randomId(), invoice.recipient.pubkeyHex),
    });
    expect(newInvoice.body.error.code).toBe(draining);
    const newConsignment = await postConsignment(
      newTransfer(invoice.invoiceId),
      "new",
    );
    expect(newConsignment.body.error.code).toBe(draining);
    // ...before the invoice and the signature are checked
    const unreserved = await postConsignment(
      newTransfer(randomId()),
      "unreserved",
    );
    expect(unreserved.body.error.code).toBe(draining);
    const badSignature = await postConsignment(
      newTransfer(invoice.invoiceId),
      "bad signature",
      { signature: "00".repeat(64) },
    );
    expect(badSignature.body.error.code).toBe(draining);
    const newOp = await ackPrepareOp(ackOperation());
    expect(newOp.body.error.code).toBe(draining);

    // ...while repeating accepted ones is still idempotent
    expect((await rpc("invoice.prepare", invoiceParams)).body.result).toBe(
      false,
    );
    expect((await postConsignment(transfer, "pending")).body.result).toBe(
      false,
    );
    expect((await ackPrepareOp(op)).body.result).toBe(false);

    // Calls reading or completing pending transfers keep working
    expect((await rpc("server.info", {})).body.result).toBeDefined();
    expect(await invoiceStatus(invoice.invoiceId)).toBeDefined();
    expect((await transferList(invoice)).body.result).toBeDefined();
    expect((await ackGet(op)).body.result).toBeDefined();
    expect(
      (await postMedia(transfer, "a".repeat(64), "media")).body.result,
    ).toBe(true);
    expect(
      (
        await transferAction(
          "retrieved",
          transfer.transferId,
          invoice.recipient,
        )
      ).body.result,
    ).toBe(true);
    for (const t of op.transfers) {
      expect((await ackPost(t, true)).body.error).toBeUndefined();
    }

    // The recipient is done, but the sender has not retrieved the responses
    expect(countPending()).toBe(pending - 1);
    expect((await ackGet(op)).body.result.acks).toEqual({
      [op.transfers[0].transferId]: true,
      [op.transfers[1].transferId]: true,
    });
    expect(countPending()).toBe(pending - 2);
  });
});
