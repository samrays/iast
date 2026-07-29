/**
 * Two questions the Node agent's design hangs on. Both answered before writing a hook.
 *
 * The first is the fix for what `context-spike.mjs` found: binding the context to a callback at
 * enqueue time should make a pooled callback see its originating request.
 *
 * The second is more fundamental, and it is the reason this file exists separately. The JVM
 * agent tracks taint in an **identity-keyed** side table — `IdentityHashMap<Object, TaintedValue>`
 * — and that identity semantics is one of the three properties producing zero false positives
 * across 1,572 OWASP Benchmark cases. Two equal strings are not the same value; an engine keyed
 * on equality reports every query containing a word a user happened to type.
 *
 * In JavaScript, string primitives have no identity. There is nothing to key on. So the question
 * is not "how do we port the JVM design" but "does the JVM design port at all".
 *
 *   node agents/runtime/node-agent/spike/taint-key-spike.mjs
 */

import { AsyncLocalStorage, AsyncResource } from "node:async_hooks";

const store = new AsyncLocalStorage();
const results = [];
const check = (name, ok, note = "") => results.push({ name, ok, note });

// --- 1. Does explicit binding fix the pooled callback? ---------------------------------

function makePool() {
  const queue = [];
  // Not unref'd: this drain loop is the only pending work, and an unref'd timer would let the
  // process exit before the callback ever ran.
  const timer = setInterval(() => {
    const job = queue.shift();
    if (job) job();
  }, 1);
  // The agent hook would wrap here: capture the caller context at enqueue time.
  return { query: (_sql, cb) => queue.push(AsyncResource.bind(cb)), stop: () => clearInterval(timer) };
}

const pool = makePool();

await store.run({ traceId: "req-1" }, async () => {
  await new Promise((resolve) => {
    pool.query("SELECT 1", () => {
      check(
        "bound pooled callback sees its request",
        store.getStore()?.traceId === "req-1",
        "AsyncResource.bind at enqueue is the fix",
      );
      resolve();
    });
  });
});
pool.stop();

// --- 2. Can taint be keyed on identity, as it is on the JVM? ---------------------------

// A WeakMap is the closest thing JS has to an identity-keyed side table.
const table = new WeakMap();

// The value a source would return: an ordinary string primitive.
const fromRequest = "alice";
// A completely unrelated constant the application wrote itself.
const constantInCode = "alice";

try {
  table.set(fromRequest, { tainted: true });
  check("WeakMap accepts a string primitive as a key", true);
} catch {
  check(
    "WeakMap accepts a string primitive as a key",
    false,
    "it does not — primitives cannot be weakly keyed",
  );
}

// A Map does accept them, but it keys on *value*, which is exactly the semantics that produces
// false positives: the application's own constant is indistinguishable from the user's input.
const valueKeyed = new Map();
valueKeyed.set(fromRequest, { tainted: true });
check(
  "a value-keyed table can tell them apart",
  !valueKeyed.has(constantInCode),
  "it cannot — the app's own constant now reads as tainted",
);

// Boxed String objects do have identity, but no application produces them.
const boxed = new String("alice");
const otherBoxed = new String("alice");
const boxedTable = new WeakMap();
boxedTable.set(boxed, { tainted: true });
check(
  "boxed String objects have distinct identity",
  boxedTable.has(boxed) && !boxedTable.has(otherBoxed),
  "true, but real code produces primitives, not boxes",
);

// And the property the JVM relies on, stated directly.
check(
  "two equal primitives are distinguishable",
  fromRequest !== constantInCode,
  "they are not — === is value equality for primitives",
);

let failed = 0;
for (const { name, ok, note } of results) {
  if (!ok) failed++;
  console.log(`${ok ? "  ok  " : " FAIL "} ${name.padEnd(46)} ${note}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
