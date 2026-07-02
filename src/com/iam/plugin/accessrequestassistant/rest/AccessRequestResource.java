package com.iam.plugin.accessrequestassistant.rest;

import java.util.List;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;

import com.iam.plugin.accessrequestassistant.service.AccessRequestService;
import com.iam.plugin.accessrequestassistant.service.ExplainService;
import com.iam.plugin.accessrequestassistant.service.NarrativeMode;
import com.iam.plugin.accessrequestassistant.util.PluginLog;

import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.rest.plugin.AllowAll;
import sailpoint.rest.plugin.BasePluginResource;
import sailpoint.tools.GeneralException;

@Path("accessrequestassistant")
@Produces(MediaType.APPLICATION_JSON)
public class AccessRequestResource extends BasePluginResource {

    private static final Logger log = LogManager.getLogger(AccessRequestResource.class);

    private static final String DATABRICKS_NOT_CONFIGURED_MESSAGE =
        "Databricks AI is not configured. Configure databricksHost, databricksEndpoint, "
            + "and databricksToken in plugin settings.";

    @Override
    public String getPluginName() {
        return "accessRequestAssistant";
    }

    private final SailPointContext context = SailPointFactory.peekCurrentContext();
    private final AccessRequestService service = new AccessRequestService();
    private final ExplainService explainService = new ExplainService();

    /**
     * Context only — facts from live IIQ (no decision, no narrative).
     */
    @GET
    @Path("/workitems/{workItemId}/context")
    @AllowAll
    public Response getWorkItemContext(
            @PathParam("workItemId") String workItemId,
            @QueryParam("historyLookbackDays") Integer historyLookbackDays,
            @Context HttpHeaders headers) throws GeneralException {
        log.info("[API] GET /context workItemId={}", workItemId);
        long t0 = PluginLog.mark();
        try {
            int lookback = historyLookbackDays != null
                ? historyLookbackDays
                : getSettingInt("historyLookbackDays", 90);
            int maxPeers = getSettingInt("maxPeersScan", 40);
            JSONObject ctx = service.buildAccessRequestContext(context, workItemId, lookback, maxPeers);
            service.logContextSummary(ctx);
            log.info("[API] GET /context complete workItemId={} ms={}", workItemId, PluginLog.elapsed(t0));
            return Response.ok(ctx.toMap()).build();
        } catch (Exception e) {
            log.error("[API] context failed workItemId={} ms={}", workItemId, PluginLog.elapsed(t0), e);
            return Response.serverError()
                .entity(new JSONObject().put("error", e.getMessage()).toString())
                .build();
        }
    }

    /**
     * AI Review Brief — Java builds flag context; LLM applies prompt rules when configured
     * (same pattern as Certification Launcher). Java rule engine is fallback for template/offline.
     *
     * {@code narrativeMode} default {@code auto}: Databricks when host/endpoint/token are set.
     * Query param {@code ?narrativeMode=} overrides per request.
     */
    @GET
    @Path("/workitems/{workItemId}/ai-brief")
    @AllowAll
    public Response getWorkItemAIBrief(
            @PathParam("workItemId") String workItemId,
            @QueryParam("historyLookbackDays") Integer historyLookbackDays,
            @QueryParam("narrativeMode") String narrativeModeOverride,
            @QueryParam("explain") @DefaultValue("true") boolean explain,
            @Context HttpHeaders headers) throws GeneralException {

        String currentUser = resolveCurrentUser(headers);
        NarrativeMode requestedMode = resolveNarrativeMode(narrativeModeOverride);
        log.info("[API] GET /ai-brief workItemId={} user={} narrativeMode={} explain={}",
            workItemId, currentUser, requestedMode.getSettingValue(), explain);

        long t0 = PluginLog.mark();
        try {
            if (context == null) throw new GeneralException("SailPointContext is null");

            int lookback = historyLookbackDays != null
                ? historyLookbackDays
                : getSettingInt("historyLookbackDays", 90);
            int maxPeers = getSettingInt("maxPeersScan", 40);

            long tContext = PluginLog.mark();
            JSONObject accessContext = service.buildAccessRequestContext(
                context, workItemId, lookback, maxPeers);
            log.debug("[API] context phase ms={}", PluginLog.elapsed(tContext));
            service.logContextSummary(accessContext);

            NarrativeMode.DatabricksServiceConfig dbCfg = readDatabricksConfig();
            PluginLog.logDatabricksConfig(log,
                dbCfg.host, dbCfg.endpoint, dbCfg.token);

            boolean includeNarrative = explain && requestedMode != NarrativeMode.CONTEXT_ONLY;

            long tResolve = PluginLog.mark();
            ExplainService.AiBriefResult briefResult = explainService.resolve(
                requestedMode, accessContext, includeNarrative, dbCfg);
            JSONObject decision = briefResult.decision;
            log.info("[API] resolve phase ms={} llmCalled={} recommendation={} decisionSource={}",
                PluginLog.elapsed(tResolve),
                briefResult.llmCalled,
                decision.optString("recommendation"),
                briefResult.meta != null ? briefResult.meta.optString("decisionSource") : "?");

            JSONObject result = new JSONObject();
            result.put("workItemId", workItemId);
            result.put("accessContext", accessContext);
            result.put("decision", decision);
            result.put("recommendation", decision.getString("recommendation"));
            result.put("confidence", decision.getDouble("confidence"));
            if (decision.has("dataQuality")) {
                result.put("dataQuality", decision.getJSONObject("dataQuality"));
            }
            if (decision.has("confidenceLevel")) {
                result.put("confidenceLevel", decision.getString("confidenceLevel"));
            }
            result.put("rulesFired", decision.getJSONArray("rulesFired"));
            result.put("ruleSetVersion", decision.getString("ruleSetVersion"));
            if (decision.has("ruleDetails")) {
                result.put("ruleDetails", decision.getJSONArray("ruleDetails"));
            }
            if (decision.has("decisionBasis")) {
                result.put("decisionBasis", decision.getString("decisionBasis"));
            }
            if (decision.has("source")) {
                result.put("decisionSource", decision.getString("source"));
            }

            boolean llmCalled = briefResult.llmCalled;
            NarrativeMode effectiveMode = requestedMode.resolve(dbCfg);
            result.put("aiEnabled", llmCalled);
            result.put("narrativeModeEffective", effectiveMode.getSettingValue());
            maybeDatabricksNotConfiguredMessage(result, requestedMode, dbCfg, llmCalled);

            if (briefResult.meta != null) {
                result.put("_meta", briefResult.meta);
                if (briefResult.meta.has("decisionSource")) {
                    result.put("decisionSource", briefResult.meta.getString("decisionSource"));
                }
            }

            if (briefResult.narrative != null) {
                JSONObject narrative = briefResult.narrative;
                result.put("narrative", narrative);
                if (llmCalled) {
                    result.put("aiBrief", narrative);
                }
                result.put("summary", narrative.optString("summary"));
                result.put("keyFactors", narrative.optJSONArray("keyFactors"));
                result.put("openQuestions", narrative.optJSONArray("openQuestions"));
                result.put("suggestedApproverChecks", narrative.optJSONArray("suggestedApproverChecks"));
            } else if (!includeNarrative) {
                result.put("aiEnabled", false);
            }

            log.info("[API] ai-brief complete workItemId={} totalMs={} aiEnabled={} narrativeSource={} narrativeModeEffective={}",
                workItemId, PluginLog.elapsed(t0), llmCalled,
                briefResult.narrative != null ? briefResult.narrative.optString("source") : "none",
                effectiveMode.getSettingValue());
            return Response.ok(result.toMap()).build();

        } catch (java.io.IOException ioEx) {
            log.error("[API] Databricks API call failed workItemId={} totalMs={}",
                workItemId, PluginLog.elapsed(t0), ioEx);
            return Response.status(Response.Status.SERVICE_UNAVAILABLE)
                .entity(new JSONObject()
                    .put("error", "AI service unavailable: " + ioEx.getMessage())
                    .put("aiEnabled", false)
                    .toString())
                .build();
        } catch (Exception e) {
            log.error("[API] ai-brief failed workItemId={} totalMs={}", workItemId, PluginLog.elapsed(t0), e);
            return Response.serverError()
                .entity(new JSONObject().put("error", e.getMessage()).put("aiEnabled", false).toString())
                .build();
        }
    }

    private NarrativeMode resolveNarrativeMode(String queryOverride) {
        if (queryOverride != null && !queryOverride.trim().isEmpty()) {
            log.info("[Config] narrativeMode from query param: {}", queryOverride);
            return NarrativeMode.fromSetting(queryOverride);
        }
        String fromPlugin = getSettingString("narrativeMode");
        log.debug("[Config] narrativeMode from plugin setting: {}", fromPlugin);
        return NarrativeMode.fromSetting(fromPlugin);
    }

    private void maybeDatabricksNotConfiguredMessage(
            JSONObject result,
            NarrativeMode requestedMode,
            NarrativeMode.DatabricksServiceConfig dbCfg,
            boolean llmCalled) {
        if (!llmCalled && !dbCfg.isConfigured()
                && requestedMode.resolve(dbCfg) == NarrativeMode.LLM) {
            result.put("message", DATABRICKS_NOT_CONFIGURED_MESSAGE);
        }
    }

    private NarrativeMode.DatabricksServiceConfig readDatabricksConfig() {
        return new NarrativeMode.DatabricksServiceConfig(
            getSettingString("databricksHost"),
            getSettingString("databricksEndpoint"),
            getSettingString("databricksToken")
        );
    }

    private String resolveCurrentUser(HttpHeaders headers) {
        List<String> userHeader = headers.getRequestHeader("Current-User");
        if (userHeader != null && !userHeader.isEmpty() && userHeader.get(0) != null && !userHeader.get(0).isEmpty()) {
            return userHeader.get(0);
        }
        return "spadmin";
    }

    private int getSettingInt(String name, int defaultValue) {
        try {
            String v = getSettingString(name);
            if (v != null && !v.isEmpty()) return Integer.parseInt(v);
        } catch (Exception ignored) { }
        return defaultValue;
    }
}
