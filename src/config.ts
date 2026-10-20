// Strict parsing of the numeric environment variables: an unset (or empty)
// variable gets its default, while an invalid one is refused, as a silently
// ignored or misread value (e.g. MAX_POW_DIFFICULTY=0x10 read as 0) would be
// dangerous. Callers let the error stop the startup

function parseEnvInt(
  name: string,
  fallback: number,
  min: number,
  max: number,
): number {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return fallback;
  const value = /^\d+$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    const range =
      max === Number.MAX_SAFE_INTEGER
        ? `at least ${min}`
        : `between ${min} and ${max}`;
    throw new Error(
      `Invalid ${name} "${raw}" (expected a plain decimal integer, ${range})`,
    );
  }
  return value;
}

export function parsePositiveInt(
  name: string,
  fallback: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  return parseEnvInt(name, fallback, 1, max);
}

export function parseNonNegativeInt(
  name: string,
  fallback: number,
  max = Number.MAX_SAFE_INTEGER,
): number {
  return parseEnvInt(name, fallback, 0, max);
}

const DEFAULT_PORT = 3000;
const MAX_PORT = 65535;

export function parsePort(): number {
  return parsePositiveInt("PORT", DEFAULT_PORT, MAX_PORT);
}
