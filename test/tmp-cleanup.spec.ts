import fs from "fs";
import path from "path";

import app from "../src/app";
import {
  closeApiEndpoints,
  loadApiEndpoints,
  runGC,
} from "../src/controllers/api";
import { nowSecs } from "./helpers";

const hourSecs = 3600;

const tempDir = fs.mkdtempSync(path.join(__dirname, "temp-tmp-cleanup-"));
const appData = path.join(tempDir, "app-data");
const tmp = path.join(appData, "tmp");

function writeTmpFile(name: string, ageSecs = 0): string {
  const file = path.join(tmp, name);
  fs.writeFileSync(file, "partial upload");
  // A negative age is in the future, e.g. -0.5 is later in the current second
  const time = nowSecs() - ageSecs;
  fs.utimesSync(file, time, time);
  return file;
}

beforeAll(() => {
  // Leftovers of a previous run, including a recent one
  fs.mkdirSync(tmp, { recursive: true });
  writeTmpFile("old", 2 * hourSecs);
  writeTmpFile("recent");
  // Written earlier in the current second: its mtime is fractional, so it is
  // after the whole-second now
  writeTmpFile("fractional", -0.5);
  process.env.APP_DATA = appData;
  loadApiEndpoints(app);
});

afterAll(() => {
  closeApiEndpoints();
  return fs.promises.rm(tempDir, { recursive: true, force: true });
});

describe("temp dir cleanup", () => {
  it("removes all the leftovers at startup", () => {
    expect(fs.readdirSync(tmp)).toEqual([]);
  });

  it("removes only the old files in GC", () => {
    writeTmpFile("old", 2 * hourSecs);
    writeTmpFile("recent", hourSecs - 60);

    runGC();
    expect(fs.readdirSync(tmp)).toEqual(["recent"]);

    runGC(nowSecs() + 2 * hourSecs);
    expect(fs.readdirSync(tmp)).toEqual([]);
  });
});
