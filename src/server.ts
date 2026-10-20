import dotenv from "dotenv";

import app from "./app";
import { parseNonNegativeInt, parsePort } from "./config";
import {
  closeApiEndpoints,
  countPending,
  loadApiEndpoints,
  startDraining,
} from "./controllers/api";

dotenv.config();

const DEFAULT_SHUTDOWN_TIMEOUT_SECS = 300;
const DRAIN_CHECK_INTERVAL_MS = 5000;
// setTimeout fires after 1 ms for a delay above 2^31-1 ms, so the timeouts in
// seconds can't exceed this (about 24.8 days)
const MAX_TIMEOUT_SECS = 2147483;

// An invalid configuration stops the startup. The error is reported here, with
// a failure exit code, as the logger would only log it and let the process
// exit successfully
function exitOnStartupError(e: unknown): never {
  console.error(`Startup failed: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
}

let shutdownTimeoutSecs: number;
// 0: wait indefinitely
let drainTimeoutSecs: number;
try {
  // Read after dotenv
  app.set("port", parsePort());
  shutdownTimeoutSecs = parseNonNegativeInt(
    "SHUTDOWN_TIMEOUT_SECS",
    DEFAULT_SHUTDOWN_TIMEOUT_SECS,
    MAX_TIMEOUT_SECS,
  );
  drainTimeoutSecs = parseNonNegativeInt(
    "DRAIN_TIMEOUT_SECS",
    0,
    MAX_TIMEOUT_SECS,
  );
  loadApiEndpoints(app);
} catch (e) {
  exitOnStartupError(e);
}

/**
 * Start Express server.
 */
const server = app.listen(app.get("port"), () => {
  console.log(
    "  App is running at http://localhost:%d in %s mode",
    app.get("port"),
    app.get("env"),
  );
  console.log("  Press CTRL-C to stop\n");
});

// While shutting down, a connection whose call was in flight when the shutdown
// started becomes idle once the response is sent, and would otherwise be kept
// open until the keep-alive timeout, delaying the exit
server.on("request", (_req, res) => {
  res.on("finish", () => {
    if (app.get("shuttingDown"))
      setImmediate(() => server.closeIdleConnections());
  });
});

/**
 * Graceful shutdown: stop accepting new connections, let pending calls
 * complete, then release resources and exit. Calls still pending after
 * SHUTDOWN_TIMEOUT_SECS are aborted (clients are expected to retry).
 */
const shutdown = (reason: string) => {
  if (app.get("shuttingDown")) {
    console.log(`${reason}, already shutting down`);
    return;
  }
  app.set("shuttingDown", true);
  clearDrainTimers();

  const timeoutSecs = shutdownTimeoutSecs;
  console.log(
    `${reason}, shutting down (waiting up to ${timeoutSecs}s for pending calls)`,
  );

  setTimeout(() => {
    console.error("Shutdown timeout reached, aborting pending calls");
    server.closeAllConnections();
    closeApiEndpoints();
    process.exit(1);
  }, timeoutSecs * 1000).unref();

  server.close((err) => {
    closeApiEndpoints();
    if (err) {
      console.error(`Error closing the server: ${err}`);
      process.exit(1);
    }
    console.log("Shutdown complete");
    process.exit(0);
  });
  server.closeIdleConnections();
};

/**
 * Drain mode, to retire an instance: calls starting a new transfer are refused,
 * the ones completing pending transfers keep working, and the server shuts down
 * gracefully once nothing is pending. Pending transfers can last until their
 * expiration (plus the retention grace), so DRAIN_TIMEOUT_SECS can be set to
 * cap the wait. SIGTERM/SIGINT during a drain transitions the server to a
 * graceful shutdown.
 */
let drainCheckTimer: NodeJS.Timeout | undefined;
let drainTimeoutTimer: NodeJS.Timeout | undefined;

const clearDrainTimers = () => {
  clearInterval(drainCheckTimer);
  clearTimeout(drainTimeoutTimer);
};

const drain = () => {
  if (drainCheckTimer || app.get("shuttingDown")) {
    console.log("Received SIGUSR2, already draining or shutting down");
    return;
  }
  startDraining();

  const checkPending = () => {
    if (countPending() === 0) shutdown("Drain complete");
  };

  const pending = countPending();
  console.log(`Received SIGUSR2, draining (${pending} pending)`);
  drainCheckTimer = setInterval(checkPending, DRAIN_CHECK_INTERVAL_MS);
  drainCheckTimer.unref();
  if (pending === 0) return shutdown("Drain complete");

  if (drainTimeoutSecs > 0) {
    drainTimeoutTimer = setTimeout(() => {
      shutdown(`Drain timeout reached (${countPending()} still pending)`);
    }, drainTimeoutSecs * 1000);
    drainTimeoutTimer.unref();
  }
};

process.on("SIGTERM", () => shutdown("Received SIGTERM"));
process.on("SIGINT", () => shutdown("Received SIGINT"));
process.on("SIGUSR2", drain);

export default server;
