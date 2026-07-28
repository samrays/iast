package dev.aegis.agent.runtime;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Reads HTTP facts off a servlet request without ever naming the servlet API.
 *
 * <p>This class is published to the <b>bootstrap</b> class loader, which can see {@code
 * java.base} and nothing else. {@code jakarta.servlet.http.HttpServletRequest} lives on the
 * application's loader, so a compile-time reference here would not merely be inelegant — it
 * would fail to resolve at runtime, in the customer's process, the first time a request
 * arrived. Reflection is therefore the only option available, not a stylistic preference.
 *
 * <p>Reflection on a per-request path has to be paid for once, not on every call. Methods are
 * resolved once per concrete request class and cached in a {@link ClassValue}, which the JVM
 * keys off the class itself: entries die with the class loader that defined them, so a
 * redeployed web application does not leak its old classes through the agent.
 *
 * <p>Every accessor is resolved <em>on the servlet interface</em>, never on the container's
 * implementation type. Tomcat's {@code RequestFacade} and Jetty's {@code Request} are public,
 * but plenty of wrappers are not, and invoking a public method through a package-private class
 * throws {@code IllegalAccessException}. Going through the interface makes the call legal
 * whatever the container did with its own visibility.
 */
public final class HttpFacade {

    /** Interfaces we accept as "this is an HTTP request", newest first. */
    private static final String[] REQUEST_INTERFACES = {
        "jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest",
    };

    /**
     * Attributes frameworks use to publish the matched route pattern.
     *
     * <p>Worth the lookup: grouping findings by raw path would give a separate finding per id
     * in {@code /users/1}, {@code /users/2}, … while the actual defect is one line of code.
     */
    private static final String[] ROUTE_ATTRIBUTES = {
        "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern",
        "jakarta.ws.rs.core.UriInfo.matchedTemplate",
        "javax.ws.rs.core.UriInfo.matchedTemplate",
    };

    private static final ClassValue<Accessors> ACCESSORS =
            new ClassValue<>() {
                @Override
                protected Accessors computeValue(Class<?> type) {
                    return Accessors.forType(type);
                }
            };

    private HttpFacade() {}

    /** True when this object is an HTTP servlet request of either API generation. */
    public static boolean isHttpRequest(Object request) {
        return request != null && ACCESSORS.get(request.getClass()).usable();
    }

    /**
     * Populate the context from the request.
     *
     * <p>Failure is not propagated: an unreadable request means a finding with less evidence,
     * never a broken application.
     */
    public static void describe(Object request, RequestContext context) {
        if (request == null || context == null) {
            return;
        }
        Accessors accessors = ACCESSORS.get(request.getClass());
        if (!accessors.usable()) {
            return;
        }
        context.withHttp(
                accessors.invokeString(request, accessors.method),
                accessors.invokeString(request, accessors.requestUri),
                accessors.invokeString(request, accessors.remoteAddr));
    }

    /**
     * The route pattern the framework matched, or an empty string.
     *
     * <p>Read at request <em>exit</em>: the attribute does not exist yet on the way in, because
     * the framework has not matched a handler at that point.
     */
    public static String routeTemplate(Object request) {
        if (request == null) {
            return "";
        }
        Accessors accessors = ACCESSORS.get(request.getClass());
        if (accessors.attribute == null) {
            return "";
        }
        for (String key : ROUTE_ATTRIBUTES) {
            Object value = accessors.invoke(request, accessors.attribute, key);
            if (value instanceof String pattern && !pattern.isEmpty()) {
                return pattern;
            }
        }
        return "";
    }

    /** Whether the container has an authenticated principal for this request. */
    public static boolean isAuthenticated(Object request) {
        if (request == null) {
            return false;
        }
        Accessors accessors = ACCESSORS.get(request.getClass());
        return accessors.invoke(request, accessors.remoteUser) != null
                || accessors.invoke(request, accessors.userPrincipal) != null;
    }

    /** The cookie's name, for evidence. Falls back to {@code "cookie"} when unreadable. */
    public static String cookieName(Object cookie) {
        if (cookie == null) {
            return "cookie";
        }
        try {
            Method getName = cookie.getClass().getMethod("getName");
            Object name = getName.invoke(cookie);
            return name instanceof String value && !value.isEmpty() ? value : "cookie";
        } catch (ReflectiveOperationException | RuntimeException e) {
            return "cookie";
        }
    }

    /** Resolved once per concrete request class. Null entries mean "not available here". */
    static final class Accessors {

        private static final Accessors UNUSABLE = new Accessors(null, null, null, null, null, null);

        final Method method;
        final Method requestUri;
        final Method remoteAddr;
        final Method attribute;
        final Method remoteUser;
        final Method userPrincipal;

        private Accessors(
                Method method,
                Method requestUri,
                Method remoteAddr,
                Method attribute,
                Method remoteUser,
                Method userPrincipal) {
            this.method = method;
            this.requestUri = requestUri;
            this.remoteAddr = remoteAddr;
            this.attribute = attribute;
            this.remoteUser = remoteUser;
            this.userPrincipal = userPrincipal;
        }

        static Accessors forType(Class<?> type) {
            Class<?> iface = servletRequestInterface(type);
            if (iface == null) {
                return UNUSABLE;
            }
            return new Accessors(
                    lookup(iface, "getMethod"),
                    lookup(iface, "getRequestURI"),
                    lookup(iface, "getRemoteAddr"),
                    lookup(iface, "getAttribute", String.class),
                    lookup(iface, "getRemoteUser"),
                    lookup(iface, "getUserPrincipal"));
        }

        boolean usable() {
            return requestUri != null;
        }

        private static Class<?> servletRequestInterface(Class<?> type) {
            for (Class<?> candidate : allInterfaces(type)) {
                for (String name : REQUEST_INTERFACES) {
                    if (candidate.getName().equals(name)) {
                        return candidate;
                    }
                }
            }
            return null;
        }

        private static List<Class<?>> allInterfaces(Class<?> type) {
            List<Class<?>> found = new ArrayList<>(8);
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                collect(current.getInterfaces(), found);
            }
            return found;
        }

        private static void collect(Class<?>[] interfaces, List<Class<?>> found) {
            for (Class<?> candidate : interfaces) {
                if (found.contains(candidate)) {
                    continue;
                }
                found.add(candidate);
                collect(candidate.getInterfaces(), found);
            }
        }

        private static Method lookup(Class<?> iface, String name, Class<?>... parameters) {
            try {
                return iface.getMethod(name, parameters);
            } catch (NoSuchMethodException e) {
                // An older or cut-down servlet API. The caller degrades rather than failing.
                return null;
            }
        }

        Object invoke(Object target, Method accessor, Object... arguments) {
            if (accessor == null) {
                return null;
            }
            try {
                return accessor.invoke(target, arguments);
            } catch (ReflectiveOperationException | RuntimeException e) {
                // Containers throw from these accessors in edge states — a recycled request, an
                // async dispatch that has already completed. Evidence is optional; the
                // application is not.
                return null;
            }
        }

        String invokeString(Object target, Method accessor) {
            Object value = invoke(target, accessor);
            return value instanceof String text ? text : "";
        }
    }
}
