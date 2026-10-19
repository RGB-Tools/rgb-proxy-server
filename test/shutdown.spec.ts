import { ChildProcess, spawn } from "child_process";
import fs from "fs";
import http from "http";
import net from "net";
import path from "path";

import {
  ackOperation,
  apiClient,
  httpTransport,
  newTransfer,
  sleep,
  waitFor,
} from "./helpers";

// Signal handling can't be exercised in-process, so these tests run the
// compiled server (src/server.ts) as a child process

// Each test starts one or more servers and waits for them to exit
jest.setTimeout(40000);

const draining = -115;
// How long a server may take to exit after it is done: right away (the
// margin covers the process startup and shutdown), or, for a drain, at most
// one check interval (5s) later
const exitMs = 2000;
const drainExitMs = 7000;

const tempDir = fs.mkdtempSync(path.join(__dirname, "temp-shutdown-"));
const servers: RunningServer[] = [];

afterAll(async () => {
  for (const s of servers) s.kill();
  await fs.promises.rm(tempDir, { recursive: true, force: true });
});

interface Exit {
  code: number | null;
  signal: NodeJS.Signals | null;
}

interface RunningServer {
  port: number;
  client: ReturnType<typeof apiClient>;
  output: () => string;
  exit: () => Exit | undefined;
  signal: (signal: NodeJS.Signals) => void;
  waitForOutput: (text: string, timeoutMs?: number) => Promise<boolean>;
  waitForExit: (timeoutMs?: number) => Promise<boolean>;
  kill: () => void;
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, () => {
      const { port } = srv.address() as net.AddressInfo;
      srv.close(() => resolve(port));
    });
  });
}

async function startServer(env: Record<string, string> = {}) {
  const port = await freePort();
  const child: ChildProcess = spawn(
    process.execPath,
    [path.join(__dirname, "..", "src", "server.js")],
    {
      env: {
        ...process.env,
        APP_DATA: fs.mkdtempSync(path.join(tempDir, "app-data-")),
        PORT: String(port),
        POW_RATE_THRESHOLD: "1000000",
        POW_GLOBAL_THRESHOLD: "1000000",
        ...env,
      },
    },
  );
  let output = "";
  let exit: Exit | undefined;
  child.stdout?.on("data", (d) => (output += d));
  child.stderr?.on("data", (d) => (output += d));
  child.on("exit", (code, signal) => (exit = { code, signal }));

  const server: RunningServer = {
    port,
    client: apiClient(httpTransport(`http://127.0.0.1:${port}`)),
    output: () => output,
    exit: () => exit,
    signal: (signal) => child.kill(signal),
    waitForOutput: (text, timeoutMs = 5000) =>
      waitFor(() => output.includes(text), timeoutMs),
    waitForExit: (timeoutMs = exitMs) =>
      waitFor(() => exit !== undefined, timeoutMs),
    kill: () => {
      if (!exit) child.kill("SIGKILL");
    },
  };
  servers.push(server);
  expect(await server.waitForOutput("App is running", 10000)).toBe(true);
  return server;
}

// Sends a call whose body is completed after the given delay, so that it is
// still in flight when a signal arrives
function slowServerInfo(
  server: RunningServer,
  delayMs: number,
): Promise<number | undefined> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: "1",
    method: "server.info",
  });
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        port: server.port,
        method: "POST",
        path: "/json-rpc",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    );
    req.on("error", reject);
    req.write(body.slice(0, 10));
    setTimeout(() => req.end(body.slice(10)), delayMs);
  });
}

// Leaves a transfer pending, and returns what is needed to complete it
async function postPendingTransfer(server: RunningServer) {
  const invoice = await server.client.prepareInvoice();
  const transfer = newTransfer(invoice.invoiceId);
  expect(
    (await server.client.postConsignment(transfer, "pending")).result,
  ).toBe(true);
  return { invoice, transfer };
}

describe("SIGTERM", () => {
  it("lets pending calls complete, then exits", async () => {
    const server = await startServer();

    const inFlight = slowServerInfo(server, 500);
    await sleep(100);
    server.signal("SIGTERM");
    await sleep(200);
    expect(server.exit()).toBeUndefined();
    expect(await inFlight).toBe(200);

    expect(await server.waitForExit()).toBe(true);
    expect(server.exit()).toEqual({ code: 0, signal: null });
    expect(server.output()).toContain("Received SIGTERM, shutting down");
    expect(server.output()).toContain("Shutdown complete");
  });
});

describe("SIGUSR2 (drain mode)", () => {
  it("shuts down right away when nothing is pending", async () => {
    const server = await startServer();

    server.signal("SIGUSR2");
    expect(await server.waitForExit()).toBe(true);
    expect(server.exit()).toEqual({ code: 0, signal: null });
    expect(server.output()).toContain("draining (0 pending)");
    expect(server.output()).toContain("Drain complete, shutting down");
  });

  it("waits for the recipient and the sender to complete", async () => {
    const server = await startServer();
    const { client } = server;
    const { invoice, transfer } = await postPendingTransfer(server);
    const op = await client.ackPrepare(2);

    server.signal("SIGUSR2");
    expect(await server.waitForOutput("draining (2 pending)")).toBe(true);
    server.signal("SIGUSR2");
    expect(await server.waitForOutput("already draining")).toBe(true);
    const refused = await client.rpc("ack.prepare", ackOperation().params);
    expect(refused.error.code).toBe(draining);

    // The recipient acts on the transfer and on the operation...
    await client.transferAction(
      "retrieved",
      transfer.transferId,
      invoice.recipient,
    );
    for (const t of op.transfers) await client.ackPost(t, true);

    // ...but the server only exits once the sender has retrieved the responses
    await sleep(6000); // longer than the drain check interval
    expect(server.exit()).toBeUndefined();
    expect((await client.ackGet(op)).result.acks).toBeDefined();

    expect(await server.waitForExit(drainExitMs)).toBe(true);
    expect(server.exit()).toEqual({ code: 0, signal: null });
    expect(server.output()).toContain("Drain complete, shutting down");
  });

  it("gives up waiting after DRAIN_TIMEOUT_SECS", async () => {
    const server = await startServer({ DRAIN_TIMEOUT_SECS: "2" });
    await postPendingTransfer(server);

    server.signal("SIGUSR2");
    expect(await server.waitForExit(exitMs + 2000)).toBe(true);
    expect(server.exit()).toEqual({ code: 0, signal: null });
    expect(server.output()).toContain(
      "Drain timeout reached (1 still pending)",
    );
  });

  it("is turned into a graceful shutdown by SIGTERM", async () => {
    const server = await startServer();
    await postPendingTransfer(server);

    server.signal("SIGUSR2");
    expect(await server.waitForOutput("draining (1 pending)")).toBe(true);
    // Still running as the transfer is pending
    await sleep(300);
    expect(server.exit()).toBeUndefined();

    // SIGTERM with a call in flight: the call completes, then the server exits
    // cleanly without waiting for the pending transfer
    const inFlight = slowServerInfo(server, 500);
    await sleep(100);
    server.signal("SIGTERM");
    await sleep(200);
    expect(server.exit()).toBeUndefined();
    expect(await inFlight).toBe(200);

    expect(await server.waitForExit()).toBe(true);
    expect(server.exit()).toEqual({ code: 0, signal: null });
    expect(server.output()).toContain("Received SIGTERM, shutting down");
    expect(server.output()).toContain("Shutdown complete");
    expect(server.output()).not.toContain("Drain complete");
  });
});
