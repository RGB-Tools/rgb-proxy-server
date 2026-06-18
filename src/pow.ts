import crypto from "crypto";

// Adaptive proof of work required on consignment.post (protocol change spec,
// Appendix C).
//
// The difficulty for an invoice is d = min(d_max, max(d_rate, d_global)):
// - d_rate depends on the recent calls for the invoice
// - d_global depends on the recent calls across all invoices
//
// Each term is computed from a call count that decays exponentially with time
// constant T (windowSecs), so that a steady rate of r calls per second settles
// at about r * T, i.e. it approximates the number of calls in the last T
// seconds, with older calls weighing less. The computed term is 0 while the
// count is below the threshold and rises by 1 bit for each further step:
//   computed = count < threshold ? 0 : floor((count - threshold) / step) + 1
// capped at d_max.
//
// The term in effect rises instantly as soon as the computed value is higher
// and decreases only once the current value has been in effect for at least H
// (holdSecs), at which point it drops to the computed value (possibly 0).
// The hysteresis is applied to each term separately, as d_global changes with
// calls to other invoices.
//
// All times are in seconds (possibly fractional) and are always passed in by
// the caller, so the logic can be tested with an injected clock. Reading the
// difficulty has no side effects: the level in effect at a given time is
// derived from the state recorded at the last counted call, so only counted
// calls change the state.

export interface DifficultyParams {
  // d_max: the maximum difficulty, 0 disables the proof of work
  maxDifficulty: number;
  // decayed call count at which the difficulty becomes 1
  threshold: number;
  // decayed calls above the threshold for each additional bit
  step: number;
  // T: time constant of the exponential decay of the call count
  windowSecs: number;
  // H: minimum time a difficulty stays in effect before it can decrease
  holdSecs: number;
}

export interface PowConfig {
  maxDifficulty: number;
  rateThreshold: number;
  rateStep: number;
  globalThreshold: number;
  globalStep: number;
  windowSecs: number;
  holdSecs: number;
}

// Decayed counts below this are negligible and their trackers can be dropped
const IDLE_COUNT = 0.01;

export class DifficultyTracker {
  private count = 0;
  private countAt = 0;
  private level = 0;
  private since = 0;

  constructor(private readonly params: DifficultyParams) {}

  // Call count at time `t`. The count decays exponentially with time and each
  // call adds 1 to it, so the decayed sum of the calls up to the last one
  // (`count`, recorded at `countAt`) is enough to derive it at any later `t`,
  // with no need to keep the timestamps of the single calls.
  private decayedCount(t: number): number {
    if (this.count === 0) return 0;
    const elapsed = Math.max(0, t - this.countAt);
    return this.count * Math.exp(-elapsed / this.params.windowSecs);
  }

  private computed(count: number): number {
    const { maxDifficulty, threshold, step } = this.params;
    if (count < threshold) return 0;
    return Math.min(maxDifficulty, Math.floor((count - threshold) / step) + 1);
  }

  // Level in effect at `now` and the time it took effect, without changing
  // the state. Between counted calls the count only decays, so the computed
  // value can only decrease: the level drops at the first time, at least H
  // after it took effect, the computed value is lower than it.
  private settle(now: number): { level: number; since: number } {
    const { threshold, step, windowSecs, holdSecs } = this.params;
    let level = this.level;
    let since = this.since;
    while (level > 0) {
      const earliest = since + holdSecs;
      // the hold time has not passed yet, so keep the current level
      if (earliest > now) break;
      // drop the level to the new computed value if it's lower than the current one,
      // setting `since` to the earliest time the drop could have happened
      const computed = Math.min(
        level,
        this.computed(this.decayedCount(earliest)),
      );
      if (computed < level) {
        level = computed;
        since = earliest;
        continue;
      }
      // The computed value at `earliest` is not lower than `level`, so the
      // level is kept past `earliest` and drops by 1 bit as soon as the
      // decayed count goes below `levelFloor`, the lowest count giving
      // `level`. Since the count decays exponentially, the time of this
      // `crossing` can be computed directly, solving
      // count * exp(-(t - countAt) / T) = levelFloor for t.
      // After the drop the new level has been in effect since `crossing`, so
      // the loop goes on to check whether it can drop further.
      const levelFloor = threshold + (level - 1) * step;
      const crossing = Math.max(
        earliest,
        this.countAt + windowSecs * Math.log(this.count / levelFloor),
      );
      if (crossing > now) break;
      level -= 1;
      since = crossing;
    }
    return { level, since };
  }

  // Difficulty in effect at `now` (read-only)
  current(now: number): number {
    return this.settle(now).level;
  }

  // Count a call made at `now`, possibly raising the difficulty
  record(now: number): void {
    // first settle the level to the current one
    const { level, since } = this.settle(now);
    // then update the count to now, then add the new call and update
    // the time of the last recorded call
    this.count = this.decayedCount(now) + 1;
    this.countAt = now;
    // raise the level, if needed
    const computed = this.computed(this.count);
    if (computed > level) {
      this.level = computed;
      this.since = now;
    } else {
      this.level = level;
      this.since = since;
    }
  }

  // Whether the tracker holds no state worth keeping.
  // A cutoff is necessary since the decayed count only approaches 0, never reaching it.
  idle(now: number): boolean {
    return this.current(now) === 0 && this.decayedCount(now) < IDLE_COUNT;
  }
}

export class ProofOfWork {
  private readonly global: DifficultyTracker;
  private readonly invoices = new Map<string, DifficultyTracker>();

  constructor(readonly config: PowConfig) {
    this.global = new DifficultyTracker(this.globalParams());
  }

  private globalParams(): DifficultyParams {
    return {
      maxDifficulty: this.config.maxDifficulty,
      threshold: this.config.globalThreshold,
      step: this.config.globalStep,
      windowSecs: this.config.windowSecs,
      holdSecs: this.config.holdSecs,
    };
  }

  private rateParams(): DifficultyParams {
    return {
      maxDifficulty: this.config.maxDifficulty,
      threshold: this.config.rateThreshold,
      step: this.config.rateStep,
      windowSecs: this.config.windowSecs,
      holdSecs: this.config.holdSecs,
    };
  }

  get enabled(): boolean {
    return this.config.maxDifficulty > 0;
  }

  // Difficulty currently required to create a transfer for the invoice
  // (read-only, also for unknown invoices)
  difficulty(invoiceId: string, now: number): number {
    if (!this.enabled) return 0;
    const rate = this.invoices.get(invoiceId)?.current(now) ?? 0;
    return Math.min(
      this.config.maxDifficulty,
      Math.max(rate, this.global.current(now)),
    );
  }

  // Count a call for the invoice towards both d_rate and d_global
  record(invoiceId: string, now: number): void {
    if (!this.enabled) return;
    let tracker = this.invoices.get(invoiceId);
    if (!tracker) {
      tracker = new DifficultyTracker(this.rateParams());
      this.invoices.set(invoiceId, tracker);
    }
    tracker.record(now);
    this.global.record(now);
  }

  // Drop the state of an invoice whose data has been deleted
  forget(invoiceId: string): void {
    this.invoices.delete(invoiceId);
  }

  // Drop the state of invoices that have had no recent calls
  prune(now: number): void {
    for (const [invoiceId, tracker] of this.invoices) {
      if (tracker.idle(now)) this.invoices.delete(invoiceId);
    }
  }
}

// Number of leading zero bits, starting from the most significant bit of the
// first byte
export function leadingZeroBits(digest: Buffer): number {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

export function powDigest(
  transferId: string,
  powTimestamp: string,
  powNonce: string,
): Buffer {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(transferId + powTimestamp + powNonce, "utf8"))
    .digest();
}

// Whether the nonce solves the puzzle for the given difficulty
export function verifyPowSolution(
  transferId: string,
  powTimestamp: string,
  powNonce: string,
  difficulty: number,
): boolean {
  return (
    leadingZeroBits(powDigest(transferId, powTimestamp, powNonce)) >= difficulty
  );
}
