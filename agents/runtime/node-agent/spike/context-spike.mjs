/**
 * Does a request context survive Node's event loop?
 *
 * This is the Node agent's equivalent of the JVM's bootstrap-loader constraint: the thing that
 * decides the shape of everything else, and which is far cheaper to establish deliberately than
 * to discover three failures in.
 *
 * On the JVM, async propagation was a feature — something added once the synchronous path
 * worked. In Node almost nothing is synchronous, so if the context does not survive the event
 * loop then the taint table is scoped to nothing and every finding is lost *silently*, which is
 * the worst failure this product has.
 *
 * Each case below is a real shape from application code, not a language exercise. The last two
 * are the ones that actually decide the design.
 *
 *   node agents/runtime/node-agent/spike/context-spike.mjs
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";

const store = new AsyncLocalStorage();
const results = [];

/** Read the context the way a sink hook would: no arguments, just "what request am I in?". */
const current = () => store.getStore()?.traceId ?? null;

function check(name, actual, note = "") {
  const ok = actual === "req-1";
  results.push({ name, ok, actual, note });
}

async function afterAwait() {
  await new Promise((resolve) => setTimeout(resolve, 1));
  check("after await", current());
}

function insidePromiseChain() {
  return Promise.resolve()
    .then(() => new Promise((resolve) => setImmediate(resolve)))
    .then(() => check("inside .then() chain", current()));
}

function insideCallback() {
  return new Promise((resolve) => {
    setTimeout(() => {
      check("inside setTimeout callback", current());
      resolve();
    }, 1);
  });
}

function insideEventHandler(emitter) {
  return new Promise((resolve) => {
    // Listener registered inside the request, fired inside the request.
    emitter.once("data", () => {
      check("inside EventEmitter listener", current());
      resolve();
    });
    setImmediate(() => emitter.emit("data"));
  });
}

async function insideStream() {
  const stream = Readable.from(["chunk"]);
  for await (const _chunk of stream) {
    check("inside for-await over a stream", current());
  }
}

/**
 * The case that decides the design.
 *
 * A connection pool accepts a callback during the request and invokes it later from its own
 * async context — the pool's, not the caller's. If the context does not follow the callback
 * here, then every database sink in every pooled application is invisible, which is most
 * applications and the most important sink.
 */
function pooledCallback(pool) {
  return new Promise((resolve) => {
    pool.query("SELECT 1", () => {
      check("inside a pooled callback", current(), "the case that decides the design");
      resolve();
    });
  });
}

/** A pool that drains its queue outside any request, exactly as a real one does. */
function makePool() {
  const queue = [];
  // The drain loop is started *before* any request exists, so it has no context of its own.
  setInterval(() => {
    const job = queue.shift();
    if (job) job();
  }, 1).unref();
  return { query: (_sql, cb) => queue.push(cb) };
}

const pool = makePool();
const emitter = new EventEmitter();

await store.run({ traceId: "req-1" }, async () => {
  await afterAwait();
  await insidePromiseChain();
  await insideCallback();
  await insideEventHandler(emitter);
  await insideStream();
  await pooledCallback(pool);
});

// And the property that matters just as much: no leakage between requests.
await store.run({ traceId: "req-2" }, async () => {
  await new Promise((resolve) => setTimeout(resolve, 1));
  results.push({
    name: "second request sees its own context",
    ok: current() === "req-2",
    actual: current(),
    note: "a leak here bleeds one user's data into another's finding",
  });
});

results.push({
  name: "outside any request",
  ok: current() === null,
  actual: current(),
  note: "must be null, or every background task looks like a request",
});

let failed = 0;
for (const { name, ok, actual, note } of results) {
  if (!ok) failed++;
  console.log(`${ok ? "  ok  " : " FAIL "} ${name.padEnd(38)} ${String(actual).padEnd(8)} ${note}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed === 0 ? 0 : 1);
