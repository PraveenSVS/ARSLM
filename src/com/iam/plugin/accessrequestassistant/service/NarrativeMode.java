package com.iam.plugin.accessrequestassistant.service;

/**
 * Plugin setting {@code narrativeMode} controls whether {@code /ai-brief} calls Databricks.
 * Default {@link #AUTO} — LLM prompt rules when Databricks is configured (Certification Launcher pattern).
 *
 * <p>Override per request via {@code ?narrativeMode=}. Databricks host/endpoint/token use the
 * same three settings as Certification Launcher when mode is {@link #LLM} or {@link #AUTO}.
 */
public enum NarrativeMode {

    CONTEXT_ONLY("context_only"),
    /** Deterministic summary from rulesFired — default; does not call Databricks. */
    TEMPLATE("template"),
    /** Log prompts at INFO; template in response. */
    LLM_DRY_RUN("llm_dry_run"),
    /** Live Databricks call (requires databricksHost, databricksEndpoint, databricksToken). */
    LLM("llm"),
    /** Databricks configured → {@link #LLM}; not configured → {@link #TEMPLATE}. */
    AUTO("auto");

    private final String settingValue;

    NarrativeMode(String settingValue) {
        this.settingValue = settingValue;
    }

    public String getSettingValue() {
        return settingValue;
    }

    /** Parse plugin setting or query param; empty/null → {@link #AUTO}. */
    public static NarrativeMode fromSetting(String raw) {
        if (raw == null || raw.trim().isEmpty()) {
            return AUTO;
        }
        String n = raw.trim().toLowerCase().replace('-', '_');
        for (NarrativeMode mode : values()) {
            if (mode.settingValue.equals(n)) {
                return mode;
            }
        }
        if ("context".equals(n) || "facts_only".equals(n)) return CONTEXT_ONLY;
        if ("dry_run".equals(n) || "llm_preview".equals(n)) return LLM_DRY_RUN;
        if ("meta_llm".equals(n) || "databricks".equals(n)) return LLM;
        return TEMPLATE;
    }

    /** Effective mode after {@link #AUTO} resolves against Databricks configuration. */
    public NarrativeMode resolve(DatabricksServiceConfig databricksConfig) {
        if (this != AUTO) {
            return this;
        }
        return databricksConfig.isConfigured() ? LLM : TEMPLATE;
    }

    public boolean mayCallDatabricks() {
        return this == LLM || this == AUTO || this == LLM_DRY_RUN;
    }

    /** Same three plugin settings as Certification Launcher. */
    public static class DatabricksServiceConfig {
        public final String host;
        public final String endpoint;
        public final String token;

        public DatabricksServiceConfig(String host, String endpoint, String token) {
            this.host = host;
            this.endpoint = endpoint;
            this.token = token;
        }

        public boolean isConfigured() {
            return host != null && !host.isEmpty()
                && endpoint != null && !endpoint.isEmpty()
                && token != null && !token.isEmpty();
        }

        public String invocationsUrl() {
            String h = host.endsWith("/") ? host.substring(0, host.length() - 1) : host;
            return h + "/serving-endpoints/" + endpoint + "/invocations";
        }
    }
}
