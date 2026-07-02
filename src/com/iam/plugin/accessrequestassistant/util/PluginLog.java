package com.iam.plugin.accessrequestassistant.util;

import org.apache.logging.log4j.Logger;

/** Structured log helpers for the Access Request AI Assistant plugin. */
public final class PluginLog {

    private PluginLog() {
    }

    public static long mark() {
        return System.currentTimeMillis();
    }

    public static long elapsed(long startMs) {
        return System.currentTimeMillis() - startMs;
    }

    /**
     * Context-builder step timing. Grep IIQ logs for {@code [Context][Q1]} through {@code [Q8]}.
     *
     * @param detail SLF4J-style message after {@code ms={}}, e.g. {@code "login={} name={}"}
     */
    public static void contextStep(Logger log, String step, long startMs, String detail, Object... args) {
        long ms = elapsed(startMs);
        if (args == null || args.length == 0) {
            log.info("[Context][{}] ms={} {}", step, ms, detail);
            return;
        }
        Object[] all = new Object[1 + args.length];
        all[0] = ms;
        System.arraycopy(args, 0, all, 1, args.length);
        log.info("[Context][" + step + "] ms={} " + detail, all);
    }

    /** Log Databricks settings without exposing token values. */
    public static void logDatabricksConfig(Logger log, String host, String endpoint, String token) {
        boolean tokenSet = token != null && !token.trim().isEmpty();
        boolean hostSet = host != null && !host.trim().isEmpty();
        boolean endpointSet = endpoint != null && !endpoint.trim().isEmpty();
        log.info("[Config] databricks hostConfigured={} endpoint={} tokenConfigured={}",
            hostSet, endpointSet ? endpoint : "(empty)", tokenSet);
        if (hostSet && endpointSet) {
            String h = host.endsWith("/") ? host.substring(0, host.length() - 1) : host;
            log.debug("[Config] databricks invocationsUrl={}/serving-endpoints/{}/invocations", h, endpoint);
        }
    }
}
