import { AsyncLocalStorage } from "async_hooks";

export interface TaintRange {
  start: number;
  end: number;
  sourceKind: string;
  sourceName: string;
}

export interface TaintRecord {
  value: string;
  ranges: TaintRange[];
}

export interface RequestTraceContext {
  traceId: string;
  route: string;
  method: string;
  sources: Array<{ kind: string; name: string; value: string }>;
}

const traceStorage = new AsyncLocalStorage<RequestTraceContext>();
const taintRegistry = new Map<string, TaintRecord>();

export function startTraceContext<T>(
  traceId: string,
  route: string,
  method: str,
  fn: () => T
): T {
  const context: RequestTraceContext = {
    traceId,
    route,
    method,
    sources: [],
  };
  return traceStorage.run(context, fn);
}

export function getCurrentTrace(): RequestTraceContext | undefined {
  return traceStorage.getStore();
}

export function markTainted(value: string, sourceKind: string, sourceName: string): string {
  if (!value || typeof value !== "string") {
    return value;
  }

  const record: TaintRecord = {
    value,
    ranges: [{ start: 0, end: value.length, sourceKind, sourceName }],
  };

  taintRegistry.set(value, record);

  const trace = getCurrentTrace();
  if (trace) {
    trace.sources.push({ kind: sourceKind, name: sourceName, value: value.substring(0, 100) });
  }

  return value;
}

export function isTainted(value: unknown): { tainted: boolean; record?: TaintRecord } {
  if (typeof value !== "string") {
    return { tainted: false };
  }

  const exact = taintRegistry.get(value);
  if (exact) {
    return { tainted: true, record: exact };
  }

  // Check substring matches for concatenated queries
  for (const [key, record] of taintRegistry.entries()) {
    if (value.includes(key)) {
      return { tainted: true, record };
    }
  }

  return { tainted: false };
}
