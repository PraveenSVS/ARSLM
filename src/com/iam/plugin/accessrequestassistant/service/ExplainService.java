package com.iam.plugin.accessrequestassistant.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

/**
 * Resolves access-request advisory: LLM applies prompt rules when Databricks is available
 * (Certification Launcher pattern); Java rule engine is fallback for template/offline modes.
 */
public class ExplainService {

    private static final Logger log = LogManager.getLogger(ExplainService.class);

    private static final int MAX_TOKENS = 680;

    private final AccessRequestService accessRequestService = new AccessRequestService();
    private final AccessRequestRuleEngine ruleEngine = new AccessRequestRuleEngine();

    public static class AiBriefResult {
        public final JSONObject decision;
        public final JSONObject narrative;
        public final JSONObject meta;
        public final boolean llmCalled;

        public AiBriefResult(JSONObject decision, JSONObject narrative, JSONObject meta, boolean llmCalled) {
            this.decision = decision;
            this.narrative = narrative;
            this.meta = meta;
            this.llmCalled = llmCalled;
        }
    }
    /**
     * Resolve decision + optional narrative. LLM path decides via prompt rules; template path uses Java rules.
     */
    public AiBriefResult resolve(
            NarrativeMode requestedMode,
            JSONObject accessContext,
            boolean includeNarrative,
            NarrativeMode.DatabricksServiceConfig databricksConfig) throws java.io.IOException {

        NarrativeMode mode = requestedMode.resolve(databricksConfig);
        JSONObject meta = new JSONObject();
        meta.put("narrativeModeRequested", requestedMode.getSettingValue());
        meta.put("narrativeModeEffective", mode.getSettingValue());

        if (mode == NarrativeMode.CONTEXT_ONLY || !includeNarrative) {
            JSONObject decision = ruleEngine.evaluate(accessContext);
            meta.put("decisionSource", "java_rules");
            if (!includeNarrative) {
                meta.put("narrativeSkipped", true);
            }
            return new AiBriefResult(decision, null, meta, false);
        }

        String systemPrompt = accessRequestService.buildAISystemPrompt();
        String userMessage = accessRequestService.buildAIUserMessage(accessContext);

        if (mode == NarrativeMode.TEMPLATE) {
            return javaRulesWithTemplate(accessContext, meta);
        }

        if (mode == NarrativeMode.LLM_DRY_RUN) {
            JSONObject wouldSend = buildWouldSendLlm(databricksConfig, systemPrompt, userMessage);
            meta.put("llmCallSkipped", true);
            meta.put("llmDryRun", true);
            meta.put("wouldSendLlm", wouldSend);
            log.info(
                "[LLM DRY-RUN] workItemId={} endpoint={} systemPromptChars={} userMessageChars={} — NOT calling Databricks",
                accessContext.optString("workItemId"),
                wouldSend.optString("endpointUrl", "(not configured)"),
                systemPrompt.length(),
                userMessage.length()
            );
            log.info("[LLM DRY-RUN] systemPrompt:\n{}", systemPrompt);
            log.info("[LLM DRY-RUN] userMessage:\n{}", userMessage);
            AiBriefResult result = javaRulesWithTemplate(accessContext, meta);
            if (result.narrative != null) {
                result.narrative.put("source", "template_dry_run");
            }
            return result;
        }

        if (!databricksConfig.isConfigured()) {
            log.warn("[AI Brief] Databricks not configured — Java rule fallback workItemId={}",
                accessContext.optString("workItemId"));
            meta.put("llmCallSkipped", true);
            meta.put("llmFallbackReason", "databricks_not_configured");
            AiBriefResult result = javaRulesWithTemplate(accessContext, meta);
            if (result.narrative != null) {
                result.narrative.put("source", "template_fallback");
            }
            return result;
        }

        log.info("[AI Brief] Sending to LLM — workItemId={} endpoint={} maxTokens={} userMessageChars={}",
            accessContext.optString("workItemId"),
            databricksConfig.invocationsUrl(),
            MAX_TOKENS,
            userMessage.length());
        log.debug("[AI Brief] systemPrompt:\n{}", systemPrompt);
        log.debug("[AI Brief] userMessage:\n{}", userMessage);

        DatabricksService databricks = new DatabricksService(
            databricksConfig.host, databricksConfig.endpoint, databricksConfig.token);
        String raw = databricks.chatCompletion(systemPrompt, userMessage, MAX_TOKENS);
        log.debug("[AI Brief] LLM raw response — workItemId={} ({} chars):\n{}",
            accessContext.optString("workItemId"), raw.length(), raw);

        try {
            JSONObject llmResponse = new JSONObject(raw);
            JSONObject decision = accessRequestService.decisionFromLlmResponse(llmResponse);
            accessRequestService.applyContextReviewSignals(decision, accessContext);
            AccessRequestHistoryPolicy.applyConfidenceCap(decision, accessContext);
            JSONObject narrative = accessRequestService.narrativeFromLlmResponse(llmResponse);
            if (decision.has("decisionBasis")) {
                narrative.put("summary", decision.getString("decisionBasis"));
            }
            narrative = accessRequestService.compactForApprover(narrative, decision);
            meta.put("llmCallSkipped", false);
            meta.put("decisionSource", "llm_rules");
            log.info("[AI Brief] LLM decision workItemId={} recommendation={} ruleMatched={}",
                accessContext.optString("workItemId"),
                decision.optString("recommendation"),
                llmResponse.optString("ruleMatched"));
            return new AiBriefResult(decision, narrative, meta, true);
        } catch (Exception parseEx) {
            log.warn("[AI Brief] LLM response was not valid JSON — Java rule fallback. Parse error: {}. Raw: {}",
                parseEx.getMessage(), raw);
            meta.put("llmCallSkipped", true);
            meta.put("llmParseError", parseEx.getMessage());
            AiBriefResult result = javaRulesWithTemplate(accessContext, meta);
            if (result.narrative != null) {
                result.narrative.put("source", "template_fallback");
            }
            return result;
        }
    }

    private AiBriefResult javaRulesWithTemplate(JSONObject accessContext, JSONObject meta) {
        JSONObject decision = ruleEngine.evaluate(accessContext);
        AccessRequestHistoryPolicy.applyConfidenceCap(decision, accessContext);
        meta.put("decisionSource", "java_rules");
        meta.put("llmCallSkipped", true);
        JSONObject narrative = accessRequestService.templateNarrative(accessContext, decision);
        narrative.put("source", "template");
        narrative = accessRequestService.compactForApprover(narrative, decision);
        log.info("[AI Brief] Java rules workItemId={} recommendation={} rulesFired={}",
            accessContext.optString("workItemId"),
            decision.optString("recommendation"),
            decision.optJSONArray("rulesFired"));
        return new AiBriefResult(decision, narrative, meta, false);
    }

    private JSONObject buildWouldSendLlm(
            NarrativeMode.DatabricksServiceConfig cfg,
            String systemPrompt,
            String userMessage) {
        JSONObject would = new JSONObject();
        would.put("endpointUrl", cfg.isConfigured() ? cfg.invocationsUrl() : JSONObject.NULL);
        would.put("maxTokens", MAX_TOKENS);
        would.put("systemPrompt", systemPrompt);
        would.put("userMessage", userMessage);
        would.put("systemPromptChars", systemPrompt.length());
        would.put("userMessageChars", userMessage.length());
        return would;
    }
}
