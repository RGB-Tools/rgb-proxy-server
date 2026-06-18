import {
  DifficultyTracker,
  leadingZeroBits,
  powDigest,
  ProofOfWork,
  verifyPowSolution,
} from "../src/pow";

// Large T so that the decay is negligible over a few seconds
const slowDecay = {
  maxDifficulty: 24,
  threshold: 10,
  step: 2,
  windowSecs: 1e9,
  holdSecs: 600,
};

function recordMany(tracker: DifficultyTracker, count: number, at: number) {
  for (let i = 0; i < count; i++) tracker.record(at);
}

describe("proof of work puzzle", () => {
  it("counts leading zero bits from the most significant bit", () => {
    expect(leadingZeroBits(Buffer.from([0x80, 0x00]))).toBe(0);
    expect(leadingZeroBits(Buffer.from([0x40, 0x00]))).toBe(1);
    expect(leadingZeroBits(Buffer.from([0x01, 0xff]))).toBe(7);
    expect(leadingZeroBits(Buffer.from([0x00, 0x10]))).toBe(11);
    expect(leadingZeroBits(Buffer.from([0x00, 0x00]))).toBe(16);
  });

  it("hashes the UTF-8 concatenation of transfer ID, timestamp and nonce", () => {
    const digest = powDigest("tid", "1700000000", "42");
    expect(digest.toString("hex")).toBe(
      powDigest("tid1700000000", "", "42").toString("hex"),
    );
  });

  it("accepts any nonce at difficulty 0 and checks the difficulty otherwise", () => {
    expect(verifyPowSolution("tid", "1", "anything", 0)).toBe(true);
    let nonce = 0;
    while (leadingZeroBits(powDigest("tid", "1", String(nonce))) < 8) nonce++;
    const bits = leadingZeroBits(powDigest("tid", "1", String(nonce)));
    expect(verifyPowSolution("tid", "1", String(nonce), 8)).toBe(true);
    expect(verifyPowSolution("tid", "1", String(nonce), bits + 1)).toBe(false);
  });
});

describe("adaptive difficulty", () => {
  it("is 0 below the threshold and rises 1 bit per step above it", () => {
    const tracker = new DifficultyTracker(slowDecay);
    recordMany(tracker, 9, 1000);
    expect(tracker.current(1000)).toBe(0);
    tracker.record(1000); // 10 calls: threshold reached
    expect(tracker.current(1000)).toBe(1);
    tracker.record(1000);
    expect(tracker.current(1000)).toBe(1);
    tracker.record(1000); // 12 calls: one step above
    expect(tracker.current(1000)).toBe(2);
    recordMany(tracker, 4, 1000); // 16 calls
    expect(tracker.current(1000)).toBe(4);
  });

  it("is capped at the max difficulty", () => {
    const tracker = new DifficultyTracker({ ...slowDecay, maxDifficulty: 3 });
    recordMany(tracker, 100, 1000);
    expect(tracker.current(1000)).toBe(3);
  });

  it("rises instantly", () => {
    const tracker = new DifficultyTracker(slowDecay);
    recordMany(tracker, 12, 1000);
    expect(tracker.current(1000)).toBe(2);
    // a rise right after another one is not delayed by H
    recordMany(tracker, 5, 1001);
    expect(tracker.current(1001)).toBe(4);
  });

  it("decreases only after the current value has been in effect for H", () => {
    const params = { ...slowDecay, windowSecs: 100, holdSecs: 600 };
    const tracker = new DifficultyTracker(params);
    recordMany(tracker, 20, 1000);
    expect(tracker.current(1000)).toBe(6);
    // the count has fully decayed long before H, but the value holds
    expect(tracker.current(1599)).toBe(6);
    // after H it drops to the computed value, 0 here
    expect(tracker.current(1600)).toBe(0);
  });

  it("restarts the hold period on every rise", () => {
    const params = { ...slowDecay, windowSecs: 100, holdSecs: 600 };
    const tracker = new DifficultyTracker(params);
    recordMany(tracker, 12, 1000);
    expect(tracker.current(1000)).toBe(2);
    recordMany(tracker, 30, 1300);
    const raised = tracker.current(1300);
    expect(raised).toBeGreaterThan(2);
    expect(tracker.current(1600)).toBe(raised);
    expect(tracker.current(1899)).toBe(raised);
    expect(tracker.current(1900)).toBe(0);
  });

  it("decays in steps, each held for at least H", () => {
    // with a slow decay the computed value goes down 1 bit at a time
    const params = { ...slowDecay, windowSecs: 3600, holdSecs: 60 };
    const tracker = new DifficultyTracker(params);
    recordMany(tracker, 20, 0);
    expect(tracker.current(0)).toBe(6);

    let level = 6;
    let since = 0;
    const changes: { at: number; level: number }[] = [];
    const violations: { at: number; from: number; to: number }[] = [];
    for (let t = 0; t <= 20000; t++) {
      const current = tracker.current(t);
      if (current === level) continue;
      if (current > level || t - since < 60) {
        violations.push({ at: t, from: level, to: current });
      }
      changes.push({ at: t, level: current });
      level = current;
      since = t;
    }
    expect(violations).toEqual([]);
    expect(level).toBe(0);
    // the count starts decaying right away, so after H the difficulty drops
    // to the computed value
    expect(changes[0]).toEqual({ at: 60, level: 5 });
    // then the count goes below threshold + 4 * step (the lowest count for 5
    // bits) at T * ln(20 / 18)
    expect(changes[1]).toEqual({
      at: Math.ceil(3600 * Math.log(20 / 18)),
      level: 4,
    });
  });

  it("limits the oscillation around a threshold", () => {
    const params = { ...slowDecay, windowSecs: 100, holdSecs: 605 };
    const tracker = new DifficultyTracker(params);
    // calls arriving every 10 seconds keep the count around the threshold
    // (between about 9.5 and 10.5 at steady state): the difficulty rises as
    // soon as a call takes the count above it, but can only decrease once
    // it has been in effect for H
    let level = 0;
    let since = 0;
    let decreases = 0;
    const early: number[] = [];
    for (let t = 0; t < 6000; t++) {
      if (t % 10 === 0) tracker.record(t);
      const current = tracker.current(t);
      if (current === level) continue;
      if (current < level) {
        if (t - since < 605) early.push(t);
        decreases++;
      }
      level = current;
      since = t;
    }
    expect(early).toEqual([]);
    expect(decreases).toBeGreaterThan(0);
    expect(decreases).toBeLessThanOrEqual(6000 / 605);
    // after the calls stop it drops to 0 within H
    tracker.record(6000);
    expect(tracker.current(6000)).toBe(1);
    expect(tracker.current(6000 + 605)).toBe(0);
  });

  it("reading the difficulty has no side effects", () => {
    const params = { ...slowDecay, windowSecs: 100, holdSecs: 600 };
    const read = new DifficultyTracker(params);
    const unread = new DifficultyTracker(params);
    recordMany(read, 20, 1000);
    recordMany(unread, 20, 1000);
    for (let t = 1000; t < 1700; t += 7) read.current(t);
    for (const t of [1599, 1600, 2000, 5000]) {
      expect(read.current(t)).toBe(unread.current(t));
    }
  });

  it("combines the per-invoice and the global difficulty", () => {
    const pow = new ProofOfWork({
      maxDifficulty: 5,
      rateThreshold: 3,
      rateStep: 1,
      globalThreshold: 6,
      globalStep: 1,
      windowSecs: 1e9,
      holdSecs: 600,
    });
    expect(pow.enabled).toBe(true);
    for (let i = 0; i < 4; i++) pow.record("a", 1000);
    // rate for a: 4 calls -> 2 bits, global: 4 calls -> 0
    expect(pow.difficulty("a", 1000)).toBe(2);
    expect(pow.difficulty("b", 1000)).toBe(0);
    for (let i = 0; i < 3; i++) pow.record("b", 1000);
    // global: 7 calls -> 2 bits, rate for b: 3 calls -> 1 bit
    expect(pow.difficulty("b", 1000)).toBe(2);
    expect(pow.difficulty("unknown", 1000)).toBe(2);
    for (let i = 0; i < 10; i++) pow.record("a", 1000);
    // capped at the max difficulty
    expect(pow.difficulty("a", 1000)).toBe(5);
    expect(pow.difficulty("unknown", 1000)).toBe(5);
  });

  it("forgets idle invoices", () => {
    const pow = new ProofOfWork({
      maxDifficulty: 5,
      rateThreshold: 1,
      rateStep: 1,
      globalThreshold: 1000,
      globalStep: 1,
      windowSecs: 10,
      holdSecs: 60,
    });
    pow.record("a", 0);
    pow.record("a", 0);
    expect(pow.difficulty("a", 0)).toBe(2);
    pow.prune(30);
    expect(pow.difficulty("a", 30)).toBe(2);
    pow.prune(1000);
    expect(pow.difficulty("a", 1000)).toBe(0);
    pow.record("b", 0);
    pow.forget("b");
    expect(pow.difficulty("b", 0)).toBe(0);
  });

  it("is disabled with a max difficulty of 0", () => {
    const pow = new ProofOfWork({
      maxDifficulty: 0,
      rateThreshold: 1,
      rateStep: 1,
      globalThreshold: 1,
      globalStep: 1,
      windowSecs: 1e9,
      holdSecs: 600,
    });
    expect(pow.enabled).toBe(false);
    for (let i = 0; i < 10; i++) pow.record("a", 1000);
    expect(pow.difficulty("a", 1000)).toBe(0);
  });
});
