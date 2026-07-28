package dev.aegis.agent.runtime;

import dev.aegis.agent.taint.TaintTracker;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Per-request state: the taint table, the HTTP facts a finding needs, and the sampling
 * decision.
 *
 * <p>Held in a {@link ThreadLocal}. That covers the synchronous servlet model; instrumented
 * {@code Executor}, {@code ForkJoinTask} and {@code CompletableFuture} entry points copy the
 * context across thread hand-offs, because taint that vanishes at the first async boundary
 * makes the product silently under-report on exactly the modern codebases that need it.
 */
public final class RequestContext {

    private static final ThreadLocal<RequestContext> CURRENT = new ThreadLocal<>();

    private final TaintTracker tracker = new TaintTracker();
    private final String traceId;
    private final long startedAtNanos = System.nanoTime();
    private final boolean sampled;

    private String method = "";
    private String path = "";
    private String routeTemplate = "";
    private String remoteAddr = "";
    private final Map<String, String> parameters = new LinkedHashMap<>();
    private final Map<String, String> headers = new LinkedHashMap<>();
    private String bodyExcerpt = "";

    private RequestContext(String traceId, boolean sampled) {
        this.traceId = traceId;
        this.sampled = sampled;
    }

    /** Begin a request on this thread. An existing context is replaced, never nested. */
    public static RequestContext begin(String traceId, boolean sampled) {
        RequestContext context = new RequestContext(traceId, sampled);
        CURRENT.set(context);
        return context;
    }

    /** The active context, or {@code null} outside a request. Callers must tolerate null. */
    public static RequestContext current() {
        return CURRENT.get();
    }

    /**
     * End the request and release the taint table.
     *
     * <p>Called from a {@code finally} block in the entry-point advice, so an application
     * exception cannot strand a request's taint table on a pooled thread — which would both
     * leak memory and bleed one user's data into the next request on that thread.
     */
    public static void end() {
        RequestContext context = CURRENT.get();
        if (context != null) {
            context.tracker.clear();
            CURRENT.remove();
        }
    }

    /** Adopt a context on another thread, for executor and future hand-offs. */
    public static void adopt(RequestContext context) {
        if (context != null) {
            CURRENT.set(context);
        }
    }

    /** Detach without clearing: the originating thread still owns the table. */
    public static void detach() {
        CURRENT.remove();
    }

    public TaintTracker tracker() {
        return tracker;
    }

    public String traceId() {
        return traceId;
    }

    /** False when the governor degraded to sampling and this request was not selected. */
    public boolean isSampled() {
        return sampled;
    }

    public long elapsedNanos() {
        return System.nanoTime() - startedAtNanos;
    }

    public RequestContext withHttp(String method, String path, String remoteAddr) {
        this.method = method == null ? "" : method;
        this.path = path == null ? "" : path;
        this.remoteAddr = remoteAddr == null ? "" : remoteAddr;
        return this;
    }

    public RequestContext withRouteTemplate(String routeTemplate) {
        this.routeTemplate = routeTemplate == null ? "" : routeTemplate;
        return this;
    }

    public void recordParameter(String name, String value) {
        if (name != null && parameters.size() < 64) {
            parameters.put(name, value == null ? "" : value);
        }
    }

    public void recordHeader(String name, String value) {
        if (name != null && headers.size() < 64) {
            headers.put(name.toLowerCase(java.util.Locale.ROOT), value == null ? "" : value);
        }
    }

    public void recordBodyExcerpt(String excerpt) {
        this.bodyExcerpt = excerpt == null ? "" : excerpt;
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    public String routeTemplate() {
        return routeTemplate.isEmpty() ? path : routeTemplate;
    }

    public String remoteAddr() {
        return remoteAddr;
    }

    public Map<String, String> parameters() {
        return parameters;
    }

    public Map<String, String> headers() {
        return headers;
    }

    public String bodyExcerpt() {
        return bodyExcerpt;
    }
}
