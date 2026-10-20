import { spawnSync } from "child_process";
import express from "express";
import fs from "fs";
import path from "path";

import {
  parseNonNegativeInt,
  parsePort,
  parsePositiveInt,
} from "../src/config";
import { loadApiEndpoints } from "../src/controllers/api";
import { useTempDir } from "./helpers";

const name = "TEST_CONFIG_VALUE";
const set = (value?: string) => {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
};

afterEach(() => {
  set(undefined);
  delete process.env.PORT;
  delete process.env.MAX_UPLOAD_BYTES;
  delete process.env.MAX_POW_DIFFICULTY;
});

describe("numeric env parsing", () => {
  const invalid = [
    "1e9",
    "30d",
    "0x10",
    "0.5",
    "-1",
    "+1",
    " 5",
    "5 ",
    "1_000",
    "abc",
    " ",
    "99999999999999999999",
  ];

  it("uses the default when unset or empty", () => {
    for (const v of [undefined, ""]) {
      set(v);
      expect(parsePositiveInt(name, 7)).toBe(7);
      expect(parseNonNegativeInt(name, 7)).toBe(7);
    }
  });

  it("accepts plain decimal integers", () => {
    set("1");
    expect(parsePositiveInt(name, 7)).toBe(1);
    set("007");
    expect(parsePositiveInt(name, 7)).toBe(7);
    set("104857600");
    expect(parsePositiveInt(name, 7)).toBe(104857600);
    set("0");
    expect(parseNonNegativeInt(name, 7)).toBe(0);
  });

  it.each(invalid)("refuses %j, naming the variable", (value) => {
    set(value);
    expect(() => parsePositiveInt(name, 7)).toThrow(`Invalid ${name}`);
    expect(() => parseNonNegativeInt(name, 7)).toThrow(`Invalid ${name}`);
  });

  it("refuses 0 where a positive integer is needed", () => {
    set("0");
    expect(() => parsePositiveInt(name, 7)).toThrow(`Invalid ${name} "0"`);
  });

  it("enforces the maximum", () => {
    set("256");
    expect(parseNonNegativeInt(name, 7, 256)).toBe(256);
    set("257");
    expect(() => parseNonNegativeInt(name, 7, 256)).toThrow(
      "between 0 and 256",
    );
  });

  it("validates the port", () => {
    expect(parsePort()).toBe(3000);
    process.env.PORT = "8080";
    expect(parsePort()).toBe(8080);
    for (const v of ["3000abc", "0", "65536", "-1", "/tmp/sock"]) {
      process.env.PORT = v;
      expect(() => parsePort()).toThrow("Invalid PORT");
    }
  });
});

describe("startup with an invalid config", () => {
  const tempDir = useTempDir("temp-config-");

  it("refuses an invalid API setting before creating anything", () => {
    const appData = path.join(tempDir, "app-data");
    process.env.APP_DATA = appData;
    for (const [key, value] of [
      ["MAX_UPLOAD_BYTES", "1e9"],
      ["MAX_POW_DIFFICULTY", "0x10"],
      ["MAX_POW_DIFFICULTY", "257"],
    ]) {
      process.env[key] = value;
      expect(() => loadApiEndpoints(express())).toThrow(`Invalid ${key}`);
      delete process.env[key];
    }
    expect(fs.existsSync(appData)).toBe(false);
  });

  it.each([
    ["PORT", "3000abc"],
    ["SHUTDOWN_TIMEOUT_SECS", "5m"],
    ["SHUTDOWN_TIMEOUT_SECS", "2592000"],
    ["DRAIN_TIMEOUT_SECS", "abc"],
    ["DRAIN_TIMEOUT_SECS", "2147484"],
    ["MAX_QUOTA", "0"],
  ])("makes the server refuse to start with %s=%s", (key, value) => {
    const res = spawnSync(
      process.execPath,
      [path.join(__dirname, "..", "src", "server.js")],
      {
        env: {
          ...process.env,
          APP_DATA: path.join(tempDir, `app-data-${key}`),
          [key]: value,
        },
        encoding: "utf8",
        timeout: 15000,
      },
    );
    expect(res.status).not.toBe(0);
    expect(res.stderr).toContain(`Invalid ${key} "${value}"`);
    expect(res.stdout).not.toContain("App is running");
  });
});
