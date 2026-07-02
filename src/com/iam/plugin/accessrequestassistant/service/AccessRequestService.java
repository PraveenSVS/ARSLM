package com.iam.plugin.accessrequestassistant.service;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

import com.iam.plugin.accessrequestassistant.util.PluginLog;
import com.iam.plugin.accessrequestassistant.util.PluginUtil;
import com.iam.plugin.accessrequestassistant.service.AccessRequestRuleCatalog;

import sailpoint.api.SailPointContext;
import sailpoint.object.ApprovalItem;
import sailpoint.object.ApprovalSet;
import sailpoint.object.Attributes;
import sailpoint.object.Bundle;
import sailpoint.object.Filter;
import sailpoint.object.Identity;
import sailpoint.object.IdentityEntitlement;
import sailpoint.object.IdentityRequest;
import sailpoint.object.IdentityRequestItem;
import sailpoint.object.Link;
import sailpoint.object.ManagedAttribute;
import sailpoint.object.PolicyViolation;
import sailpoint.object.QueryOptions;
import sailpoint.object.WorkItem;
import sailpoint.tools.GeneralException;

/** Builds approver context from live IIQ objects (no Spark). */
public class AccessRequestService {

    private static final Logger log = LogManager.getLogger(AccessRequestService.class);
    private static final String IIQ_APP = "IIQ";
    private static final String ASSIGNED_ROLES = "assignedRoles";
    private static final int ENTITLEMENTS_CAP = 35;
    private static final int PEER_SAMPLE_CAP = 8;

    public JSONObject buildAccessRequestContext(
            SailPointContext context,
            String workItemId,
            int historyLookbackDays,
            int maxPeersScan) throws GeneralException {

        long t0 = System.currentTimeMillis();

        long tQ1 = PluginLog.mark();
        WorkItem workItem = context.getObject(WorkItem.class, workItemId);
        if (workItem == null) {
            throw new GeneralException("WorkItem not found: " + workItemId);
        }

        JSONObject data = new JSONObject();
        data.put("workItemId", workItemId);
        data.put("contextSchemaVersion", 4);
        data.put("task", workItem.getDescription() != null ? workItem.getDescription() : "");

        Attributes wiAttrs = workItem.getAttributes();
        String requestId = resolveIdentityRequestId(workItem, wiAttrs);
        data.put("requestId", requestId);
        if (wiAttrs != null && wiAttrs.get("flow") != null) {
            data.put("flow", wiAttrs.get("flow").toString());
        }
        PluginLog.contextStep(log, "Q1", tQ1, "workItem loaded requestId={}", requestId);

        long tQ2 = PluginLog.mark();
        Identity beneficiary = resolveBeneficiary(context, workItem);
        if (beneficiary == null) {
            throw new GeneralException("Beneficiary identity not found for work item: " + workItemId);
        }
        data.put("beneficiary", beneficiaryJson(beneficiary));
        PluginLog.contextStep(log, "Q2", tQ2, "beneficiary login={} name={} inactive={} employeeStatus={}",
            beneficiary.getName(), PluginUtil.displayName(beneficiary),
            isIdentityInactive(beneficiary),
            beneficiary.getAttribute("status"));

        long tQ3 = PluginLog.mark();
        List<ApprovalItem> approvalItems = extractApprovalItems(workItem);
        if (approvalItems.isEmpty()) {
            throw new GeneralException("No ApprovalItems on work item: " + workItemId);
        }
        ApprovalItem primary = approvalItems.get(0);
        data.put("item", slimApprovalItem(primary));

        String requestedApp = primary.getApplication();
        String entAttr = primary.getName();
        String entValue = PluginUtil.stringVal(primary.getValue());
        String entNeedle = entValue != null && !entValue.isEmpty() ? entValue : primary.getDisplayValue();

        Set<String> entitlementsOn = new LinkedHashSet<>();
        loadEntitlements(context, beneficiary, requestedApp, entAttr, entitlementsOn);
        List<String> entList = capList(entitlementsOn, ENTITLEMENTS_CAP);
        data.put("entitlementsOn", PluginUtil.stringListToJson(entList));
        PluginLog.contextStep(log, "Q3", tQ3, "approvalItem type={} access={} entitlementsOn={}",
            isRoleBundle(primary) ? "role" : "entitlement", entNeedle, entList.size());

        long tQ4 = PluginLog.mark();
        JSONObject catalogPolicy = fetchCatalogPolicy(context, primary);
        if (catalogPolicy != null) {
            data.put("catalogPolicy", catalogPolicy);
        }
        JSONObject approvalContext = fetchApprovalContext(context, primary);
        data.put("approvalContext", approvalContext);
        JSONObject accountContext = fetchAccountContext(context, beneficiary, primary);
        data.put("accountContext", accountContext);
        PluginLog.contextStep(log, "Q4", tQ4,
            "privateGroup={} sox={} approvalScheme={} linkDisabled={} inactive={}",
            catalogPolicy != null && catalogPolicy.optBoolean("privateGroup", false),
            catalogPolicy != null && catalogPolicy.optBoolean("sox", false),
            approvalContext.optString("approvalScheme", ""),
            accountContext.optBoolean("linkDisabled", false),
            beneficiary.isInactive());

        long tQ5 = PluginLog.mark();
        JSONObject history = fetchRequestHistory(context, primary, historyLookbackDays);
        data.put("entitlementHistory", history);
        PluginLog.contextStep(log, "Q5", tQ5, "historyLines={} approved={} denied={} open={} other={}",
            history.optInt("totalLines", 0), history.optInt("approved", 0), history.optInt("denied", 0),
            history.optInt("open", 0), history.optInt("other", 0));

        long tQ6 = PluginLog.mark();
        JSONObject timeline = fetchBeneficiaryAccessTimeline(
            context, beneficiary, primary, entList, entNeedle, historyLookbackDays);
        data.put("beneficiaryAccessTimeline", timeline);
        PluginLog.contextStep(log, "Q6", tQ6, "currentlyHas={} previouslyHad={} recentlyLost={}",
            timeline.optBoolean("currentlyHasAccess", false),
            timeline.optBoolean("previouslyHadAccess", false),
            timeline.optBoolean("recentlyLostAccess", false));

        long tQ7 = PluginLog.mark();
        JSONObject orgContext = fetchOrgContext(context, beneficiary, primary, entNeedle, maxPeersScan);
        data.put("orgContext", orgContext);
        PluginLog.contextStep(log, "Q7", tQ7, "peersWith={}/{} managerHas={} orgHolders={}",
            orgContext.optInt("peersWithEntitlementCount", 0),
            orgContext.optInt("peersSameManagerCount", 0),
            orgContext.optBoolean("managerHasEntitlement", false),
            orgContext.optInt("orgHoldersCount", -1));

        long tQ8 = PluginLog.mark();
        JSONObject policyContext = fetchPolicyContext(context, workItem, requestId);
        data.put("policyContext", policyContext);
        PluginLog.contextStep(log, "Q8", tQ8, "sodViolationCount={} accepted={}",
            policyContext.optInt("violationCount", 0),
            policyContext.optBoolean("acceptedViolations", false));

        JSONObject meta = new JSONObject();
        meta.put("buildMs", System.currentTimeMillis() - t0);
        meta.put("source", "iiq_plugin");
        data.put("_meta", meta);

        log.info("[Context] built workItemId={} login={} item={} totalMs={}",
            workItemId, beneficiary.getName(), entNeedle, meta.get("buildMs"));
        return data;
    }

    public void logContextSummary(JSONObject ctx) {
        JSONObject org = ctx.optJSONObject("orgContext");
        JSONObject hist = ctx.optJSONObject("entitlementHistory");
        JSONObject prior = ctx.optJSONObject("beneficiaryAccessTimeline");
        JSONObject polCtx = ctx.optJSONObject("policyContext");
        JSONObject ben = ctx.optJSONObject("beneficiary");
        JSONObject catalog = ctx.optJSONObject("catalogPolicy");
        JSONObject account = ctx.optJSONObject("accountContext");
        log.info("[Context] summary workItemId={} inactive={} linkDisabled={} privateGroup={} peers={}/{} "
                + "history=approved:{} denied:{} open:{} benDenied:{} sodViolations={}",
            ctx.optString("workItemId"),
            ben != null ? ben.opt("inactive") : "?",
            account != null ? account.opt("linkDisabled") : "?",
            catalog != null ? catalog.opt("privateGroup") : "?",
            org != null ? org.opt("peersWithEntitlementCount") : "?",
            org != null ? org.opt("peersSameManagerCount") : "?",
            hist != null ? hist.opt("approved") : "?",
            hist != null ? hist.opt("denied") : "?",
            hist != null ? hist.opt("open") : "?",
            prior != null ? prior.opt("beneficiaryRequestDenied") : "?",
            polCtx != null ? polCtx.opt("violationCount") : "?");
    }

    /**
     * System prompt — LLM is the rule engine (same pattern as Certification Launcher).
     * Java supplies flag JSON; prompt rules decide approve vs needs_manual_review.
     */
    public String buildAISystemPrompt() {
        return "You are an AI access request approval assistant embedded in SailPoint IdentityIQ.\n"
            + "You help approvers decide whether to grant requested access (entitlement or role).\n\n"
            + "=== YOUR ROLE ===\n"
            + "Analyze ONE access request. Java has prepared accessRequestContext with inline flags "
            + "(identityInactive, linkDisabled, privateGroup, sox, etc.). "
            + "Apply the DECISION RULES below and return recommendation + brief rationale.\n"
            + "This is an incoming GRANT request — do NOT recommend Revoke or Deny.\n\n"
            + "=== DATA DICTIONARY ===\n"
            + "Identity: identityInactive, identityUncorrelated, identityAdDisabled, userType, identityType, identityNoManager\n"
            + "Link: linkDisabled, linkLocked, linkPrivileged, wmsAccountDisabled, accountMissing\n"
            + "Catalog: privateGroup, sox, externalAccess, bundleInactive, elevatedAccess, dynamicGroup, "
            + "hasPrerequisites, prerequisiteNotMet, roleWmosProfile, temporaryAssignment\n"
            + "Policy/org: sodViolationAccepted, noPeerPattern, historyMostlyDenied, beneficiaryDeniedForAccess, "
            + "managerHasEntitlement, strongPeerPattern, historyMostlyApproved, recentlyLostAccess, reinstatementLikely, "
            + "novelEntitlementInOrg, peerPatternNotApplicable, orgHoldersCount\n"
            + "Data quality (informational — do not treat as review by themselves): novelAccess, limitedOrgHistory, "
            + "beneficiaryDeniedOnce, orgHistoryCompleted, orgHistoryPending, novelEntitlementInOrg\n\n"
            + "=== HISTORY THRESHOLDS (Java applies these before sending flags) ===\n"
            + "- historyMostlyDenied: only when org has 3+ completed requests AND 2+ denials AND denials > approvals\n"
            + "- historyMostlyApproved: only when org has 3+ completed AND 2+ approvals AND zero denials\n"
            + "- beneficiaryDeniedForAccess: only when this user was denied 2+ times for this access (one denial is NOT a pattern)\n"
            + "- novelAccess / limitedOrgHistory: thin request history — use LOW confidence on approve\n"
            + "- novelEntitlementInOrg: fewer than 5 identities hold this access org-wide — early rollout; "
            + "manager/peer precedent is NOT expected; confirm documented business requirement\n"
            + "- noPeerPattern: only when peers exist under manager AND none have access AND novelEntitlementInOrg=false\n\n"
            + "=== DECISION RULES (first matching REVIEW rule wins; else APPROVE) ===\n"
            + "REVIEW (recommendation=needs_manual_review):\n"
            + "  C1 identityInactive=true → Review\n"
            + "  C2 identityUncorrelated=true → Review\n"
            + "  C3 identityAdDisabled=true → Review\n"
            + "  C4 bundleInactive=true (role request) → Review\n"
            + "  C5 linkDisabled=true on Add → Review\n"
            + "  C6 linkLocked=true on Add → Review\n"
            + "  C7 privateGroup=true → Review\n"
            + "  C8 sox=true → Review\n"
            + "  C9 externalAccess=true → Review\n"
            + "  C10 prerequisiteNotMet=true → Review\n"
            + "  C11 elevatedAccess=true → Review\n"
            + "  C12 wmsAccountDisabled=true → Review\n"
            + "  C13 sodViolationAccepted=true → Review\n"
            + "  C14 noPeerPattern=true AND novelEntitlementInOrg=false → Review (peer gap on established access)\n"
            + "  C16 historyMostlyDenied=true → Review (only set when org threshold met)\n"
            + "  C17 recentlyLostAccess=true → Review\n"
            + "  C18 beneficiaryDeniedForAccess=true → Review (2+ denials for this user+access only)\n\n"
            + "APPROVE when no REVIEW rule matches:\n"
            + "  A1 managerHasEntitlement=true or strongPeerPattern=true or historyMostlyApproved=true → Approve\n"
            + "  A2 reinstatementLikely=true → Approve\n"
            + "  A4 novelAccess=true or limitedOrgHistory=true or novelEntitlementInOrg=true → Approve LOW confidence "
            + "(thin history or early org rollout — confirm business requirement if novelEntitlementInOrg)\n"
            + "  A3 no review signals and established history → Approve MEDIUM confidence\n\n"
            + "CONFIDENCE:\n"
            + "- HIGH only for A1 with established org history (orgHistoryCompleted>=3)\n"
            + "- LOW for A4 novel/limited history or thin data\n"
            + "- MEDIUM default otherwise\n"
            + "- beneficiaryDeniedOnce alone does NOT change recommendation\n\n"
            + "=== CONSTRAINTS ===\n"
            + "1. Use ONLY flags in accessRequestContext — do not hallucinate\n"
            + "2. recommendation must be approve or needs_manual_review only\n"
            + "3. summary: one sentence naming beneficiary and access; max 20 words; plain English not rule codes\n"
            + "4. ruleMatched: internal rule code for logging only (e.g. C7) — approvers never see this\n"
            + "5. keyFactors: always []\n"
            + "6. openQuestions/suggestedApproverChecks: [] for approve; at most one each for needs_manual_review\n"
            + "7. Return ONLY valid JSON — no markdown fences\n\n"
            + "=== OUTPUT FORMAT ===\n"
            + "{\n"
            + "  \"recommendation\": \"approve|needs_manual_review\",\n"
            + "  \"confidence\": \"HIGH|MEDIUM|LOW\",\n"
            + "  \"ruleMatched\": \"C7\",\n"
            + "  \"summary\": \"...\",\n"
            + "  \"keyFactors\": [],\n"
            + "  \"openQuestions\": [],\n"
            + "  \"suggestedApproverChecks\": []\n"
            + "}";
    }

    /** User message payload — context flags only (no pre-computed decision). */
    public String buildAIUserMessage(JSONObject accessContext) {
        JSONObject payload = new JSONObject();
        payload.put("accessRequestContext", buildLlmContext(accessContext));
        return "Analyze this access request and recommend approve or needs_manual_review.\n"
            + "Apply the DECISION RULES strictly. Name beneficiary and access in summary.\n\n"
            + payload.toString(2);
    }

    /**
     * Cert-Launcher-style flat flags for one access request (single item, not a page).
     */
    public JSONObject buildLlmContext(JSONObject ctx) {
        JSONObject llm = new JSONObject();
        llm.put("workItemId", ctx.opt("workItemId"));

        JSONObject ben = ctx.optJSONObject("beneficiary");
        if (ben != null) {
            llm.put("beneficiaryName", ben.opt("name"));
            llm.put("beneficiaryLogin", ben.opt("login"));
            if (ben.optBoolean("inactive", false)) llm.put("identityInactive", true);
            if (ben.has("correlated") && !ben.optBoolean("correlated", true)) {
                llm.put("identityUncorrelated", true);
            }
            if (ben.has("isADAccountEnabled") && !ben.optBoolean("isADAccountEnabled", true)) {
                llm.put("identityAdDisabled", true);
            }
            if (!ben.optBoolean("hasManager", true)) llm.put("identityNoManager", true);
            if (ben.has("userType")) llm.put("userType", ben.opt("userType"));
            if (ben.has("identityType")) llm.put("identityType", ben.opt("identityType"));
        }

        JSONObject item = ctx.optJSONObject("item");
        if (item != null) {
            llm.put("accessType", item.opt("type"));
            llm.put("operation", item.opt("op"));
            if (item.has("role")) llm.put("role", item.opt("role"));
            if (item.has("entitlement")) llm.put("entitlement", item.opt("entitlement"));
            if (item.has("app")) llm.put("application", item.opt("app"));
        }

        JSONObject catalog = ctx.optJSONObject("catalogPolicy");
        if (catalog != null) {
            if (catalog.optBoolean("privateGroup", false)) llm.put("privateGroup", true);
            if (catalog.optBoolean("sox", false)) llm.put("sox", true);
            if (catalog.optBoolean("externalAccess", false)) llm.put("externalAccess", true);
            if (catalog.optBoolean("bundleDisabled", false)) llm.put("bundleInactive", true);
            if (catalog.optBoolean("iiqElevatedAccess", false)) llm.put("elevatedAccess", true);
            if (catalog.optBoolean("dynamicGroup", false)) llm.put("dynamicGroup", true);
            if ("wmosProfile".equalsIgnoreCase(catalog.optString("roleType", ""))) {
                llm.put("roleWmosProfile", true);
            }
            if (catalog.has("prerequisites")) {
                String prereq = catalog.optString("prerequisites", "").trim();
                if (!prereq.isEmpty()) {
                    llm.put("hasPrerequisites", true);
                    llm.put("prerequisiteNotMet", isPrerequisiteNotMet(ctx, prereq));
                }
            }
        }

        JSONObject approval = ctx.optJSONObject("approvalContext");
        if (approval != null && approval.optBoolean("temporaryAssignment", false)) {
            llm.put("temporaryAssignment", true);
        }

        JSONObject account = ctx.optJSONObject("accountContext");
        if (account != null && account.optBoolean("applicable", true)) {
            if (account.optBoolean("linkDisabled", false)) llm.put("linkDisabled", true);
            if (account.optBoolean("linkLocked", false)) llm.put("linkLocked", true);
            if (account.optBoolean("linkPrivileged", false)) llm.put("linkPrivileged", true);
            if (account.optInt("wmsUserStatus", 1) == 0) llm.put("wmsAccountDisabled", true);
            if (!account.optBoolean("accountExists", false)) llm.put("accountMissing", true);
        }

        JSONObject policy = ctx.optJSONObject("policyContext");
        if (policy != null && policy.optInt("violationCount", 0) > 0) {
            llm.put("sodViolationAccepted", true);
        }

        JSONObject org = ctx.optJSONObject("orgContext");
        if (org != null) {
            AccessRequestAdoptionPolicy.applyAdoptionFlags(llm, org);
            int peerTotal = org.optInt("peersSameManagerCount", 0);
            int peerWith = org.optInt("peersWithEntitlementCount", 0);
            if (org.optBoolean("managerHasEntitlement", false)) llm.put("managerHasEntitlement", true);
            if (peerTotal > 0 && peerWith == 0) {
                if (AccessRequestAdoptionPolicy.peerPatternReviewApplicable(org)) {
                    llm.put("noPeerPattern", true);
                } else {
                    llm.put("peerPatternNotApplicable", true);
                }
            }
            if (peerTotal > 0 && peerWith >= 3) llm.put("strongPeerPattern", true);
        }

        JSONObject hist = ctx.optJSONObject("entitlementHistory");
        JSONObject timeline = ctx.optJSONObject("beneficiaryAccessTimeline");
        AccessRequestHistoryPolicy.applyHistoryFlags(llm, hist, timeline);

        JSONObject itemObj = ctx.optJSONObject("item");
        boolean requestingAdd = itemObj == null
            || !"Remove".equalsIgnoreCase(itemObj.optString("op", "Add"));
        if (requestingAdd && timeline != null && !timeline.optBoolean("currentlyHasAccess", false)) {
            if (timeline.optBoolean("recentlyLostAccess", false)) {
                llm.put("recentlyLostAccess", true);
            } else if (timeline.optBoolean("previouslyHadAccess", false)) {
                llm.put("reinstatementLikely", true);
            }
        }

        return llm;
    }

    private boolean isPrerequisiteNotMet(JSONObject ctx, String prereq) {
        JSONObject ben = ctx.optJSONObject("beneficiary");
        org.json.JSONArray ents = ctx.optJSONArray("entitlementsOn");
        java.util.List<String> entList = new java.util.ArrayList<>();
        if (ents != null) {
            for (int i = 0; i < ents.length(); i++) {
                String s = ents.optString(i, "").trim();
                if (!s.isEmpty()) entList.add(s);
            }
        }
        java.util.List<String> roles = new java.util.ArrayList<>();
        if (ben != null) {
            org.json.JSONArray assigned = ben.optJSONArray("assignedRoles");
            if (assigned != null) {
                for (int i = 0; i < assigned.length(); i++) {
                    String s = assigned.optString(i, "").trim();
                    if (!s.isEmpty()) roles.add(s);
                }
            }
        }
        return !com.iam.plugin.accessrequestassistant.util.PrerequisiteEvaluator.satisfied(prereq, entList, roles);
    }

    /**
     * All review signals derived from context flags (deterministic). Used to show every
     * applicable concern — not only the single rule the LLM picked (e.g. C1 + C5).
     */
    public org.json.JSONArray reviewSignalsFromContext(JSONObject accessContext) {
        JSONObject flags = buildLlmContext(accessContext);
        String[] reviewCodes = {
            "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10",
            "C11", "C12", "C13", "C14", "C16", "C17", "C18"
        };
        org.json.JSONArray details = new org.json.JSONArray();
        for (String code : reviewCodes) {
            if (!hasReviewFlag(code, flags)) continue;
            LlmPromptRuleCatalog.PromptRule rule = LlmPromptRuleCatalog.lookup(code);
            if (rule == null) continue;
            JSONObject row = new JSONObject();
            row.put("code", rule.javaRuleCode != null ? rule.javaRuleCode : code);
            row.put("promptCode", code);
            row.put("label", rule.label);
            row.put("rationale", rule.rationale);
            row.put("category", "review");
            row.put("source", "context");
            details.put(row);
        }
        return details;
    }

    /** Merge all context review signals into decision; primary signal is highest-priority (C1 first). */
    public void applyContextReviewSignals(JSONObject decision, JSONObject accessContext) {
        org.json.JSONArray signals = reviewSignalsFromContext(accessContext);
        if (signals.length() == 0) {
            return;
        }
        if ("needs_manual_review".equals(decision.optString("recommendation", ""))) {
            decision.put("ruleDetails", signals);
            org.json.JSONArray fired = new org.json.JSONArray();
            for (int i = 0; i < signals.length(); i++) {
                fired.put(signals.getJSONObject(i).optString("code"));
            }
            decision.put("rulesFired", fired);
        }
        JSONObject primary = signals.getJSONObject(0);
        String basis = primary.optString("label") + " — " + primary.optString("rationale");
        decision.put("decisionBasis", basis);
        LlmPromptRuleCatalog.PromptRule primaryRule =
            LlmPromptRuleCatalog.lookup(primary.optString("promptCode", ""));
        if (primaryRule != null) {
            decision.put("primaryReviewSignal", primaryRule.label);
        }
    }

    private static boolean hasReviewFlag(String code, JSONObject flags) {
        switch (code) {
            case "C1": return flags.optBoolean("identityInactive", false);
            case "C2": return flags.optBoolean("identityUncorrelated", false);
            case "C3": return flags.optBoolean("identityAdDisabled", false);
            case "C4": return flags.optBoolean("bundleInactive", false);
            case "C5": return flags.optBoolean("linkDisabled", false);
            case "C6": return flags.optBoolean("linkLocked", false);
            case "C7": return flags.optBoolean("privateGroup", false);
            case "C8": return flags.optBoolean("sox", false);
            case "C9": return flags.optBoolean("externalAccess", false);
            case "C10": return flags.optBoolean("prerequisiteNotMet", false);
            case "C11": return flags.optBoolean("elevatedAccess", false);
            case "C12": return flags.optBoolean("wmsAccountDisabled", false);
            case "C13": return flags.optBoolean("sodViolationAccepted", false);
            case "C14": return flags.optBoolean("noPeerPattern", false)
                && !flags.optBoolean("novelEntitlementInOrg", false);
            case "C16": return flags.optBoolean("historyMostlyDenied", false);
            case "C17": return flags.optBoolean("recentlyLostAccess", false);
            case "C18": return flags.optBoolean("beneficiaryDeniedForAccess", false);
            default: return false;
        }
    }

    /** Nike: IIQ inactive flag, custom inactive attribute, or Employee Status = Inactive. */
    static boolean isIdentityInactive(Identity identity) {
        if (identity == null) return false;
        if (identity.isInactive()) return true;
        if (PluginUtil.isTruthy(identity.getAttribute("inactive"))) return true;
        Object status = identity.getAttribute("status");
        if (status != null) {
            String s = status.toString().trim();
            if ("inactive".equalsIgnoreCase(s)) return true;
        }
        return false;
    }

    /** Parse LLM JSON into decision object for API response. */
    public JSONObject decisionFromLlmResponse(JSONObject llmResponse) {
        JSONObject decision = new JSONObject();
        String rec = normalizeRecommendation(llmResponse.optString("recommendation", ""));
        if (rec.isEmpty()) rec = "needs_manual_review";
        decision.put("recommendation", rec);
        String confidenceLevel = normalizeConfidenceLevel(llmResponse.optString("confidence", "MEDIUM"));
        decision.put("confidenceLevel", confidenceLevel);
        decision.put("confidence", confidenceToNumeric(confidenceLevel, rec));
        decision.put("ruleSetVersion", "llm-prompt-v1");
        decision.put("source", "llm_rules");

        String ruleMatched = llmResponse.optString("ruleMatched", "").trim();
        org.json.JSONArray rulesFired = new org.json.JSONArray();
        LlmPromptRuleCatalog.PromptRule promptRule = LlmPromptRuleCatalog.lookup(ruleMatched);
        String displayCode = promptRule != null && promptRule.javaRuleCode != null
            ? promptRule.javaRuleCode : ruleMatched;
        if (!ruleMatched.isEmpty()) rulesFired.put(displayCode);
        decision.put("rulesFired", rulesFired);

        String summary = llmResponse.optString("summary", "").trim();
        if (!ruleMatched.isEmpty()) {
            org.json.JSONArray details = new org.json.JSONArray();
            JSONObject row = new JSONObject();
            row.put("code", displayCode);
            if (promptRule != null) {
                row.put("label", promptRule.label);
                row.put("rationale", promptRule.rationale);
                if (summary.isEmpty() || isWeakApproverSummary(summary)) {
                    summary = promptRule.label + " — " + promptRule.rationale;
                }
            } else {
                row.put("label", ruleMatched);
                row.put("rationale", summary.isEmpty() ? ruleMatched : summary);
            }
            row.put("category", rec.equals("approve") ? "positive" : "review");
            row.put("source", "llm");
            details.put(row);
            decision.put("ruleDetails", details);
        }

        if (!summary.isEmpty()) {
            decision.put("decisionBasis", summary);
        }
        return decision;
    }

    private static boolean isWeakApproverSummary(String summary) {
        if (summary == null || summary.length() < 8) return true;
        String s = summary.trim();
        if (!s.contains(" ")) return true;
        String lower = s.toLowerCase(Locale.ROOT);
        return !lower.contains("review") && !lower.contains("approve")
            && !lower.contains("confirm") && !lower.contains("verify")
            && !lower.contains("disabled") && !lower.contains("inactive")
            && !lower.contains("reinstat") && !lower.contains("because")
            && !lower.contains("needs") && !lower.contains("recommend")
            && !lower.contains("warrant") && !lower.contains("prior")
            && !lower.contains("peer") && !lower.contains("account");
    }

    /** Extract narrative fields from LLM response. */
    public JSONObject narrativeFromLlmResponse(JSONObject llmResponse) {
        JSONObject out = new JSONObject();
        String summary = llmResponse.optString("summary", "").trim();
        LlmPromptRuleCatalog.PromptRule promptRule =
            LlmPromptRuleCatalog.lookup(llmResponse.optString("ruleMatched", ""));
        if (promptRule != null && (summary.isEmpty() || isWeakApproverSummary(summary))) {
            summary = promptRule.label + " — " + promptRule.rationale;
        }
        out.put("summary", summary);
        out.put("keyFactors", llmResponse.optJSONArray("keyFactors") != null
            ? llmResponse.getJSONArray("keyFactors") : new org.json.JSONArray());
        out.put("openQuestions", llmResponse.optJSONArray("openQuestions") != null
            ? llmResponse.getJSONArray("openQuestions") : new org.json.JSONArray());
        out.put("suggestedApproverChecks", llmResponse.optJSONArray("suggestedApproverChecks") != null
            ? llmResponse.getJSONArray("suggestedApproverChecks") : new org.json.JSONArray());
        if (promptRule != null) {
            out.put("ruleLabel", promptRule.label);
        }
        out.put("ruleMatched", llmResponse.opt("ruleMatched"));
        out.put("source", "llm");
        return out;
    }

    private static String normalizeRecommendation(String raw) {
        if (raw == null) return "";
        String n = raw.trim().toLowerCase().replace(' ', '_');
        if (n.contains("review") || n.contains("manual")) return "needs_manual_review";
        if (n.contains("approve")) return "approve";
        return "";
    }

    private static String normalizeConfidenceLevel(String raw) {
        if (raw == null || raw.trim().isEmpty()) return "MEDIUM";
        String n = raw.trim().toUpperCase(Locale.ROOT);
        if (n.startsWith("H")) return "HIGH";
        if (n.startsWith("L")) return "LOW";
        return "MEDIUM";
    }

    private static double confidenceToNumeric(String level, String recommendation) {
        if (level == null) level = "";
        switch (level.trim().toUpperCase()) {
            case "HIGH": return "approve".equals(recommendation) ? 0.72 : 0.68;
            case "LOW": return 0.62;
            case "MEDIUM":
            default: return "approve".equals(recommendation) ? 0.65 : 0.68;
        }
    }

    public JSONObject templateNarrative(JSONObject context, JSONObject decision) {
        JSONObject out = new JSONObject();
        String rec = decision.optString("recommendation", "needs_manual_review");
        JSONObject ben = context.optJSONObject("beneficiary");
        JSONObject item = context.optJSONObject("item");
        String login = ben != null ? ben.optString("login", "user") : "user";
        String ent = item != null
            ? (item.optString("entitlement", "").isEmpty()
                ? item.optString("role", "requested access") : item.optString("entitlement"))
            : "requested access";

        JSONArray rules = decision.optJSONArray("rulesFired");
        List<String> ruleList = new ArrayList<>();
        if (rules != null) {
            for (int i = 0; i < rules.length(); i++) ruleList.add(rules.optString(i));
        }
        ruleList = AccessRequestRuleCatalog.sortCodes(ruleList);

        boolean review = "needs_manual_review".equals(rec);
        String displayName = ben != null && !ben.optString("name", "").isEmpty()
            ? ben.optString("name") : login;
        String summary;
        if (ruleList.isEmpty()) {
            summary = displayName + " · " + ent + " — no notable review signals.";
        } else if (review) {
            summary = displayName + " · " + ent + " — review needed (mixed or elevated signals).";
        } else {
            summary = displayName + " · " + ent + " — positive signals support approval.";
        }
        out.put("summary", summary);
        out.put("keyFactors", new JSONArray());
        out.put("openQuestions", new JSONArray());
        JSONArray checks = new JSONArray();
        if (review) {
            checks.put("Confirm business justification with manager");
        }
        out.put("suggestedApproverChecks", checks);
        out.put("source", "template");
        return out;
    }

    /** Enforce scannable approver copy — rules render from {@code decision.ruleDetails}, not LLM bullets. */
    public JSONObject compactForApprover(JSONObject narrative, JSONObject decision) {
        if (narrative == null) return null;
        JSONObject out = new JSONObject(narrative.toString());
        boolean review = "needs_manual_review".equals(decision.optString("recommendation", ""));

        out.put("summary", truncateWords(out.optString("summary", ""), 22));
        out.put("keyFactors", new JSONArray());

        if (!review) {
            out.put("openQuestions", new JSONArray());
            out.put("suggestedApproverChecks", new JSONArray());
        } else {
            out.put("openQuestions", capJsonArray(out.optJSONArray("openQuestions"), 1, 90));
            out.put("suggestedApproverChecks", capJsonArray(out.optJSONArray("suggestedApproverChecks"), 1, 90));
        }
        return out;
    }

    private static String truncateWords(String text, int maxWords) {
        if (text == null || text.isEmpty()) return "";
        String[] parts = text.trim().split("\\s+");
        if (parts.length <= maxWords) return text.trim();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < maxWords; i++) {
            if (i > 0) sb.append(' ');
            sb.append(parts[i]);
        }
        return sb.append('…').toString();
    }

    private static org.json.JSONArray capJsonArray(org.json.JSONArray arr, int maxItems, int maxChars) {
        org.json.JSONArray out = new org.json.JSONArray();
        if (arr == null || arr.length() == 0) return out;
        for (int i = 0; i < arr.length() && out.length() < maxItems; i++) {
            String s = arr.optString(i, "").trim();
            if (s.isEmpty()) continue;
            if (s.length() > maxChars) s = s.substring(0, maxChars - 1) + "…";
            out.put(s);
        }
        return out;
    }

    // ── context builders ────────────────────────────────────────────────────

    private JSONObject beneficiaryJson(Identity identity) {
        JSONObject ben = new JSONObject();
        ben.put("identityId", identity.getId());
        ben.put("login", identity.getName());
        ben.put("name", PluginUtil.displayName(identity));
        boolean inactive = isIdentityInactive(identity);
        ben.put("inactive", inactive);
        ben.put("correlated", identity.isCorrelated());
        ben.put("hasManager", identity.getManager() != null);

        Object employeeStatus = identity.getAttribute("status");
        if (employeeStatus != null && !employeeStatus.toString().trim().isEmpty()) {
            ben.put("employeeStatus", employeeStatus.toString().trim());
        }

        putIfPresent(ben, "userType", identity.getAttribute("UserType"));
        if (identity.getType() != null && !identity.getType().isEmpty()) {
            ben.put("identityType", identity.getType());
        }
        Object adEnabled = identity.getAttribute("isADAccountEnabled");
        if (adEnabled != null) {
            ben.put("isADAccountEnabled", PluginUtil.isTruthy(adEnabled));
        }

        JSONArray assignedRoles = new JSONArray();
        List<Bundle> roles = identity.getAssignedRoles();
        if (roles != null) {
            for (Bundle role : roles) {
                if (role != null && role.getName() != null && !role.getName().isEmpty()) {
                    assignedRoles.put(role.getName());
                }
            }
        }
        ben.put("assignedRoles", assignedRoles);
        return ben;
    }

    private JSONObject fetchCatalogPolicy(SailPointContext context, ApprovalItem ai) throws GeneralException {
        JSONObject pol = new JSONObject();
        if (isRoleBundle(ai)) {
            String roleName = PluginUtil.stringVal(ai.getValue());
            if (roleName != null && !roleName.isEmpty()) {
                Bundle bundle = context.getObjectByName(Bundle.class, roleName);
                if (bundle != null) {
                    if (bundle.isDisabled()) pol.put("bundleDisabled", true);
                    putCatalogString(pol, "certificationPeriod", bundle.getAttribute("certificationPeriod"));
                    putCatalogSunsetDays(pol, bundle.getAttribute("sunset"));
                    putCatalogFlag(pol, "privateGroup", bundle.getAttribute("privateGroup"));
                    putCatalogFlag(pol, "externalAccess", bundle.getAttribute("externalAccess"));
                    putCatalogString(pol, "prerequisites", bundle.getAttribute("reqRoles"));
                    putCatalogString(pol, "roleType", bundle.getType());
                    putCatalogString(pol, "accessApplication", bundle.getAttribute("accessApplication"));
                    putCatalogFlag(pol, "dynamicGroup", bundle.getAttribute("dynamicGroup"));
                    putCatalogFlag(pol, "iiqElevatedAccess", bundle.getAttribute("iiqElevatedAccess"));
                }
            }
        } else {
            ManagedAttribute ma = loadManagedAttribute(context, ai);
            if (ma != null) {
                putCatalogFlag(pol, "privateGroup", ma.getAttribute("privateGroup"));
                putCatalogFlag(pol, "externalAccess", ma.getAttribute("externalAccess"));
                putCatalogString(pol, "certificationPeriod", ma.getAttribute("certificationPeriod"));
                putCatalogSunsetDays(pol, ma.getAttribute("sunset"));
                putCatalogString(pol, "prerequisites", ma.getAttribute("reqGroups"));
                putCatalogFlag(pol, "dynamicGroup", ma.getAttribute("dynamicGroup"));
                putCatalogFlag(pol, "iiqElevatedAccess", ma.getAttribute("iiqElevatedAccess"));
                if (PluginUtil.isTruthy(ma.getAttribute("privileged"))) {
                    pol.put("entitlementPrivileged", true);
                }
            }
        }
        deriveSoxFlag(pol);
        return pol.length() > 0 ? pol : null;
    }

    private JSONObject fetchAccountContext(SailPointContext context, Identity beneficiary, ApprovalItem ai) {
        JSONObject ac = new JSONObject();
        if (isRoleBundle(ai)) {
            ac.put("applicable", false);
            return ac;
        }
        String app = ai.getApplication();
        ac.put("application", app != null ? app : "");
        ac.put("applicable", true);
        if (app == null || app.isEmpty()) {
            ac.put("accountExists", false);
            return ac;
        }
        try {
            QueryOptions qo = new QueryOptions();
            qo.addFilter(Filter.and(
                Filter.eq("identity.id", beneficiary.getId()),
                Filter.eq("application.name", app)
            ));
            qo.setResultLimit(1);
            Iterator<?> it = context.search(Link.class, qo);
            if (!it.hasNext()) {
                ac.put("accountExists", false);
                return ac;
            }
            Link link = (Link) it.next();
            ac.put("accountExists", true);
            ac.put("linkDisabled", link.isDisabled());
            ac.put("linkLocked", link.isLocked());
            if (PluginUtil.isTruthy(link.getAttribute("privileged"))) {
                ac.put("linkPrivileged", true);
            }
            putWmsUserStatus(ac, link.getAttribute("User_Status"));
        } catch (GeneralException e) {
            log.warn("[Context] accountContext lookup failed app={} login={}", app, beneficiary.getName(), e);
            ac.put("accountExists", false);
        }
        return ac;
    }

    private static void putWmsUserStatus(JSONObject ac, Object raw) {
        if (raw == null) return;
        try {
            int status = raw instanceof Number
                ? ((Number) raw).intValue()
                : Integer.parseInt(raw.toString().trim());
            ac.put("wmsUserStatus", status);
        } catch (NumberFormatException ignored) {
            // ignore non-numeric WMS status
        }
    }

    private static void putCatalogFlag(JSONObject pol, String key, Object raw) {
        if (PluginUtil.isTruthy(raw)) pol.put(key, true);
    }

    private static void putCatalogString(JSONObject pol, String key, Object raw) {
        String val = PluginUtil.stringVal(raw);
        if (val != null && !val.isEmpty()) pol.put(key, val);
    }

    private static void putCatalogSunsetDays(JSONObject pol, Object raw) {
        if (raw == null) return;
        try {
            int days = raw instanceof Number
                ? ((Number) raw).intValue()
                : Integer.parseInt(raw.toString().trim());
            if (days > 0) pol.put("catalogSunsetDays", days);
        } catch (NumberFormatException ignored) {
            // non-numeric sunset values are ignored
        }
    }

    private static void deriveSoxFlag(JSONObject pol) {
        String period = pol.optString("certificationPeriod", "");
        if (!period.isEmpty() && period.toUpperCase().startsWith("SOX")) {
            pol.put("sox", true);
        }
    }

    private ManagedAttribute loadManagedAttribute(SailPointContext context, ApprovalItem ai)
            throws GeneralException {
        String app = ai.getApplication();
        String attr = ai.getName();
        String value = PluginUtil.stringVal(ai.getValue());
        if (app == null || attr == null || value == null || value.isEmpty()) return null;

        QueryOptions qo = new QueryOptions();
        qo.addFilter(Filter.and(
            Filter.eq("application.name", app),
            Filter.eq("attribute", attr),
            Filter.eq("value", value)
        ));
        qo.setResultLimit(1);
        Iterator<?> it = context.search(ManagedAttribute.class, qo);
        return it.hasNext() ? (ManagedAttribute) it.next() : null;
    }

    private void loadEntitlements(
            SailPointContext context,
            Identity beneficiary,
            String requestedApp,
            String entAttr,
            Set<String> out) throws GeneralException {

        QueryOptions qo = new QueryOptions();
        qo.addFilter(Filter.eq("identity.id", beneficiary.getId()));
        if (requestedApp != null && !requestedApp.isEmpty()) {
            qo.addFilter(Filter.eq("application.name", requestedApp));
        }
        qo.setResultLimit(200);
        Iterator<?> it = context.search(Link.class, qo);
        while (it.hasNext()) {
            Object row = it.next();
            if (!(row instanceof Link)) continue;
            collectEntitlementsFromLink((Link) row, entAttr, out);
        }

        QueryOptions entQo = new QueryOptions();
        entQo.addFilter(Filter.eq("identity.id", beneficiary.getId()));
        if (requestedApp != null && !requestedApp.isEmpty()) {
            entQo.addFilter(Filter.eq("application.name", requestedApp));
        }
        entQo.setResultLimit(ENTITLEMENTS_CAP);
        Iterator<?> entIt = context.search(IdentityEntitlement.class, entQo);
        while (entIt.hasNext()) {
            Object row = entIt.next();
            if (!(row instanceof IdentityEntitlement)) continue;
            IdentityEntitlement ie = (IdentityEntitlement) row;
            String label = formatEntitlement(ie.getName(), PluginUtil.stringVal(ie.getValue()));
            if (label != null) out.add(label);
        }
    }

    private JSONObject fetchRequestHistory(SailPointContext context, ApprovalItem ai, int lookbackDays)
            throws GeneralException {
        if (isRoleBundle(ai)) {
            return fetchRoleRequestHistory(context, ai, lookbackDays);
        }
        return fetchEntitlementHistory(context, ai, lookbackDays);
    }

    private JSONObject fetchEntitlementHistory(SailPointContext context, ApprovalItem ai, int lookbackDays)
            throws GeneralException {
        JSONObject hist = new JSONObject();
        hist.put("lookbackDays", lookbackDays);

        String app = ai.getApplication();
        String attr = ai.getName();
        String value = PluginUtil.stringVal(ai.getValue());
        if (app == null || attr == null || value == null || value.isEmpty()) {
            return emptyHistory(hist, "Insufficient match keys for history.");
        }

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, -lookbackDays);
        Date cutoff = cal.getTime();

        int approved = 0, denied = 0, open = 0, other = 0;
        QueryOptions itemQo = new QueryOptions();
        itemQo.addFilter(Filter.and(
            Filter.eq("application", app),
            Filter.eq("name", attr),
            Filter.eq("value", value)
        ));
        itemQo.setResultLimit(2000);
        Iterator<?> itemIt = context.search(IdentityRequestItem.class, itemQo);
        while (itemIt.hasNext()) {
            IdentityRequestItem iri = (IdentityRequestItem) itemIt.next();
            IdentityRequest req = resolveIdentityRequest(iri);
            if (req != null && req.getCreated() != null && req.getCreated().before(cutoff)) continue;
            switch (classifyRequestItemOutcome(iri)) {
                case APPROVED: approved++; break;
                case DENIED: denied++; break;
                case OPEN: open++; break;
                default: other++; break;
            }
        }

        int total = approved + denied + open + other;
        hist.put("totalLines", total);
        hist.put("approved", approved);
        hist.put("denied", denied);
        hist.put("open", open);
        hist.put("other", other);
        int completed = approved + denied;
        hist.put("approvalRateCompleted",
            completed > 0 ? Math.round((approved * 1000.0 / completed)) / 1000.0 : JSONObject.NULL);
        return hist;
    }

    private JSONObject fetchBeneficiaryAccessTimeline(
            SailPointContext context,
            Identity beneficiary,
            ApprovalItem ai,
            List<String> entitlementsOn,
            String entitlementNeedle,
            int lookbackDays) throws GeneralException {

        JSONObject timeline = new JSONObject();
        timeline.put("lookbackDays", lookbackDays);

        if (isRoleBundle(ai)) {
            String roleName = PluginUtil.stringVal(ai.getValue());
            boolean currentlyHas = roleName != null && identityHasRole(beneficiary, roleName);
            timeline.put("currentlyHasAccess", currentlyHas);
            return fetchRoleBeneficiaryTimeline(context, beneficiary, roleName, currentlyHas, lookbackDays, timeline);
        }

        String app = ai.getApplication();
        String attr = ai.getName();
        String value = PluginUtil.stringVal(ai.getValue());
        if (app == null || attr == null || value == null || value.isEmpty()) {
            timeline.put("currentlyHasAccess", false);
            timeline.put("previouslyHadAccess", false);
            timeline.put("recentlyLostAccess", false);
            return timeline;
        }

        boolean currentlyHas = hasEntitlementNow(entitlementsOn, attr, value, entitlementNeedle);
        timeline.put("currentlyHasAccess", currentlyHas);

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, -lookbackDays);
        Date cutoff = cal.getTime();

        QueryOptions itemQo = new QueryOptions();
        itemQo.addFilter(Filter.and(
            Filter.eq("application", app),
            Filter.eq("name", attr),
            Filter.eq("value", value),
            Filter.eq("identityRequest.targetId", beneficiary.getId()),
            Filter.ge("modified", cutoff)
        ));
        itemQo.setOrderBy("modified");
        itemQo.setOrderAscending(false);
        itemQo.setResultLimit(200);

        Date lastGrant = null;
        Date lastRemove = null;
        int beneficiaryApproved = 0;
        int beneficiaryDenied = 0;
        Iterator<?> itemIt = context.search(IdentityRequestItem.class, itemQo);
        while (itemIt.hasNext()) {
            IdentityRequestItem iri = (IdentityRequestItem) itemIt.next();
            LineOutcome outcome = classifyRequestItemOutcome(iri);
            if (outcome == LineOutcome.APPROVED) beneficiaryApproved++;
            else if (outcome == LineOutcome.DENIED) beneficiaryDenied++;
            if (outcome != LineOutcome.APPROVED) continue;

            String op = iri.getOperation();
            Date when = iri.getModified();
            if (when == null) {
                IdentityRequest req = resolveIdentityRequest(iri);
                if (req != null && req.getEndDate() != null) when = req.getEndDate();
                else if (req != null && req.getCreated() != null) when = req.getCreated();
            }
            if (when == null) continue;
            if (isGrantOperation(op) && (lastGrant == null || when.after(lastGrant))) lastGrant = when;
            else if (isRemoveOperation(op) && (lastRemove == null || when.after(lastRemove))) lastRemove = when;
        }

        boolean previouslyHad = lastGrant != null;
        boolean recentlyLost = !currentlyHas && lastRemove != null
            && (lastGrant == null || !lastGrant.after(lastRemove));

        timeline.put("previouslyHadAccess", previouslyHad);
        timeline.put("recentlyLostAccess", recentlyLost);
        timeline.put("beneficiaryRequestApproved", beneficiaryApproved);
        timeline.put("beneficiaryRequestDenied", beneficiaryDenied);
        if (lastGrant != null) timeline.put("lastSuccessfulGrant", lastGrant.getTime());
        if (lastRemove != null) timeline.put("lastSuccessfulRemove", lastRemove.getTime());
        return timeline;
    }

    private JSONObject fetchOrgContext(
            SailPointContext context,
            Identity beneficiary,
            ApprovalItem ai,
            String accessNeedle,
            int maxPeersScan) throws GeneralException {

        JSONObject org = new JSONObject();
        org.put("beneficiaryLogin", beneficiary.getName());
        org.put("accessType", isRoleBundle(ai) ? "role" : "entitlement");

        Identity manager = beneficiary.getManager();
        if (manager == null) {
            org.put("managerHasEntitlement", false);
            org.put("peersSameManagerCount", 0);
            org.put("peersWithEntitlementCount", 0);
        } else {
            org.put("managerHasEntitlement",
                identityHasRequestedAccess(context, manager, ai, accessNeedle));

            int peerTotal = 0;
            int peerWith = 0;
            JSONArray peerSample = new JSONArray();

            QueryOptions peerQo = new QueryOptions();
            peerQo.addFilter(Filter.eq("manager.id", manager.getId()));
            peerQo.addFilter(Filter.ne("id", beneficiary.getId()));
            peerQo.setResultLimit(maxPeersScan);
            Iterator<?> peerIt = context.search(Identity.class, peerQo);
            while (peerIt.hasNext()) {
                Identity peer = (Identity) peerIt.next();
                peerTotal++;
                if (identityHasRequestedAccess(context, peer, ai, accessNeedle)) {
                    peerWith++;
                    if (peerSample.length() < PEER_SAMPLE_CAP) {
                        peerSample.put(PluginUtil.displayName(peer));
                    }
                }
            }
            org.put("peersSameManagerCount", peerTotal);
            org.put("peersWithEntitlementCount", peerWith);
            if (peerSample.length() > 0) org.put("peersWithEntitlementSample", peerSample);
        }

        int orgHolders = countOrgHolders(context, ai, accessNeedle, AccessRequestAdoptionPolicy.ORG_HOLDERS_SCAN_CAP);
        org.put("orgHoldersCount", orgHolders);
        if (orgHolders >= AccessRequestAdoptionPolicy.ORG_HOLDERS_SCAN_CAP) {
            org.put("orgHoldersCountCapped", true);
        }
        return org;
    }

    private int countOrgHolders(
            SailPointContext context,
            ApprovalItem ai,
            String accessNeedle,
            int scanCap) throws GeneralException {
        if (scanCap <= 0) return 0;
        if (isRoleBundle(ai)) {
            String roleName = PluginUtil.stringVal(ai.getValue());
            if (roleName == null || roleName.isEmpty()) return 0;
            Bundle bundle = context.getObjectByName(Bundle.class, roleName);
            if (bundle == null) return 0;
            QueryOptions qo = new QueryOptions();
            qo.addFilter(Filter.contains("bundles.id", bundle.getId()));
            qo.setResultLimit(scanCap);
            int count = 0;
            Iterator<?> it = context.search(Identity.class, qo);
            while (it.hasNext()) {
                it.next();
                count++;
            }
            return count;
        }

        String app = ai.getApplication();
        String attr = ai.getName();
        String value = PluginUtil.stringVal(ai.getValue());
        if (app == null || attr == null || value == null || value.isEmpty()) {
            return 0;
        }

        QueryOptions qo = new QueryOptions();
        qo.addFilter(Filter.and(
            Filter.eq("application.name", app),
            Filter.eq("name", attr),
            Filter.eq("value", value)
        ));
        qo.setResultLimit(scanCap);
        int count = 0;
        Iterator<?> it = context.search(IdentityEntitlement.class, qo);
        while (it.hasNext()) {
            it.next();
            count++;
        }
        return count;
    }

    private JSONObject fetchApprovalContext(SailPointContext context, ApprovalItem ai) throws GeneralException {
        JSONObject approval = new JSONObject();
        if (isRoleBundle(ai)) {
            String roleName = PluginUtil.stringVal(ai.getValue());
            if (roleName != null && !roleName.isEmpty()) {
                Bundle bundle = context.getObjectByName(Bundle.class, roleName);
                if (bundle != null) {
                    putIfPresent(approval, "approvalScheme", bundle.getAttribute("approvers"));
                    putIfPresent(approval, "catalogSunsetDays", bundle.getAttribute("sunset"));
                    putSecondaryOwner(approval, bundle.getAttribute("secondaryOwner"));
                }
            }
        } else {
            ManagedAttribute ma = loadManagedAttribute(context, ai);
            if (ma != null) {
                putIfPresent(approval, "approvalScheme", ma.getAttribute("requiredApprovals"));
                putIfPresent(approval, "catalogSunsetDays", ma.getAttribute("sunset"));
                putSecondaryOwner(approval, ma.getAttribute("secondaryOwner"));
            }
        }

        Date endDate = ai.getEndDate();
        Date startDate = ai.getStartDate();
        boolean temporary = endDate != null;
        approval.put("temporaryAssignment", temporary);
        if (startDate != null) approval.put("assignmentStartDate", startDate.getTime());
        if (endDate != null) approval.put("assignmentEndDate", endDate.getTime());
        return approval;
    }

    private JSONObject fetchPolicyContext(
            SailPointContext context,
            WorkItem workItem,
            String requestId) throws GeneralException {

        JSONObject policyCtx = new JSONObject();
        JSONArray violations = new JSONArray();
        boolean accepted = false;

        IdentityRequest identityRequest = resolveIdentityRequestById(context, workItem, requestId);
        if (identityRequest != null) {
            List<?> maps = identityRequest.getPolicyViolationMaps();
            if (maps != null && !maps.isEmpty()) {
                accepted = true;
                for (Object row : maps) {
                    if (!(row instanceof java.util.Map)) continue;
                    @SuppressWarnings("unchecked")
                    java.util.Map<String, Object> map = (java.util.Map<String, Object>) row;
                    violations.put(violationFromMap(map));
                }
            }
        }

        Attributes wiAttrs = workItem.getAttributes();
        if (wiAttrs != null && wiAttrs.get("policyViolations") != null) {
            Object pv = wiAttrs.get("policyViolations");
            if (pv instanceof List && !((List<?>) pv).isEmpty()) {
                accepted = true;
                for (Object row : (List<?>) pv) {
                    if (row instanceof PolicyViolation) {
                        violations.put(violationFromObject((PolicyViolation) row));
                    } else if (row instanceof java.util.Map) {
                        @SuppressWarnings("unchecked")
                        java.util.Map<String, Object> map = (java.util.Map<String, Object>) row;
                        violations.put(violationFromMap(map));
                    }
                }
            }
        }

        policyCtx.put("acceptedViolations", accepted);
        policyCtx.put("violationCount", violations.length());
        policyCtx.put("violations", violations);
        return policyCtx;
    }

    private JSONObject fetchRoleRequestHistory(SailPointContext context, ApprovalItem ai, int lookbackDays)
            throws GeneralException {
        JSONObject hist = new JSONObject();
        hist.put("lookbackDays", lookbackDays);
        hist.put("accessType", "role");

        String roleName = PluginUtil.stringVal(ai.getValue());
        if (roleName == null || roleName.isEmpty()) {
            return emptyHistory(hist, "Insufficient role name for history.");
        }

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, -lookbackDays);
        Date cutoff = cal.getTime();

        int approved = 0, denied = 0, open = 0, other = 0;
        QueryOptions itemQo = new QueryOptions();
        itemQo.addFilter(Filter.and(
            Filter.eq("application", IIQ_APP),
            Filter.eq("name", ASSIGNED_ROLES),
            Filter.eq("value", roleName)
        ));
        itemQo.setResultLimit(2000);
        Iterator<?> itemIt = context.search(IdentityRequestItem.class, itemQo);
        while (itemIt.hasNext()) {
            IdentityRequestItem iri = (IdentityRequestItem) itemIt.next();
            IdentityRequest req = resolveIdentityRequest(iri);
            if (req != null && req.getCreated() != null && req.getCreated().before(cutoff)) continue;
            switch (classifyRequestItemOutcome(iri)) {
                case APPROVED: approved++; break;
                case DENIED: denied++; break;
                case OPEN: open++; break;
                default: other++; break;
            }
        }

        int total = approved + denied + open + other;
        hist.put("totalLines", total);
        hist.put("approved", approved);
        hist.put("denied", denied);
        hist.put("open", open);
        hist.put("other", other);
        int completed = approved + denied;
        hist.put("approvalRateCompleted",
            completed > 0 ? Math.round((approved * 1000.0 / completed)) / 1000.0 : JSONObject.NULL);
        return hist;
    }

    private JSONObject fetchRoleBeneficiaryTimeline(
            SailPointContext context,
            Identity beneficiary,
            String roleName,
            boolean currentlyHas,
            int lookbackDays,
            JSONObject timeline) throws GeneralException {

        timeline.put("accessType", "role");
        timeline.put("lookbackDays", lookbackDays);
        if (roleName == null || roleName.isEmpty()) {
            timeline.put("previouslyHadAccess", false);
            timeline.put("recentlyLostAccess", false);
            return timeline;
        }

        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_YEAR, -lookbackDays);
        Date cutoff = cal.getTime();

        QueryOptions itemQo = new QueryOptions();
        itemQo.addFilter(Filter.and(
            Filter.eq("application", IIQ_APP),
            Filter.eq("name", ASSIGNED_ROLES),
            Filter.eq("value", roleName),
            Filter.eq("identityRequest.targetId", beneficiary.getId()),
            Filter.ge("modified", cutoff)
        ));
        itemQo.setOrderBy("modified");
        itemQo.setOrderAscending(false);
        itemQo.setResultLimit(200);

        Date lastGrant = null;
        Date lastRemove = null;
        int beneficiaryApproved = 0;
        int beneficiaryDenied = 0;
        Iterator<?> itemIt = context.search(IdentityRequestItem.class, itemQo);
        while (itemIt.hasNext()) {
            IdentityRequestItem iri = (IdentityRequestItem) itemIt.next();
            LineOutcome outcome = classifyRequestItemOutcome(iri);
            if (outcome == LineOutcome.APPROVED) beneficiaryApproved++;
            else if (outcome == LineOutcome.DENIED) beneficiaryDenied++;
            if (outcome != LineOutcome.APPROVED) continue;

            String op = iri.getOperation();
            Date when = iri.getModified();
            if (when == null) {
                IdentityRequest req = resolveIdentityRequest(iri);
                if (req != null && req.getEndDate() != null) when = req.getEndDate();
                else if (req != null && req.getCreated() != null) when = req.getCreated();
            }
            if (when == null) continue;
            if (isGrantOperation(op) && (lastGrant == null || when.after(lastGrant))) lastGrant = when;
            else if (isRemoveOperation(op) && (lastRemove == null || when.after(lastRemove))) lastRemove = when;
        }

        boolean previouslyHad = lastGrant != null;
        boolean recentlyLost = !currentlyHas && lastRemove != null
            && (lastGrant == null || !lastGrant.after(lastRemove));

        timeline.put("previouslyHadAccess", previouslyHad);
        timeline.put("recentlyLostAccess", recentlyLost);
        timeline.put("beneficiaryRequestApproved", beneficiaryApproved);
        timeline.put("beneficiaryRequestDenied", beneficiaryDenied);
        if (lastGrant != null) timeline.put("lastSuccessfulGrant", lastGrant.getTime());
        if (lastRemove != null) timeline.put("lastSuccessfulRemove", lastRemove.getTime());
        return timeline;
    }

    private JSONObject violationFromMap(java.util.Map<String, Object> map) {
        JSONObject v = new JSONObject();
        v.put("policyName", stringFromMap(map, "policyName"));
        v.put("constraintName", stringFromMap(map, "constraintName"));
        v.put("description", stringFromMap(map, "description"));
        v.put("status", stringFromMap(map, "status"));
        return v;
    }

    private JSONObject violationFromObject(PolicyViolation pv) {
        JSONObject v = new JSONObject();
        v.put("policyName", pv.getPolicyName() != null ? pv.getPolicyName() : "");
        v.put("constraintName", pv.getConstraintName() != null ? pv.getConstraintName() : "");
        v.put("status", pv.getStatus() != null ? pv.getStatus().toString() : "");
        return v;
    }

    private IdentityRequest resolveIdentityRequestById(
            SailPointContext context,
            WorkItem workItem,
            String requestId) throws GeneralException {
        if (requestId != null && !requestId.isEmpty()) {
            IdentityRequest req = context.getObject(IdentityRequest.class, requestId);
            if (req != null) return req;
        }
        try {
            String wiReqId = workItem.getIdentityRequestId();
            if (wiReqId != null && !wiReqId.isEmpty()) {
                return context.getObject(IdentityRequest.class, wiReqId);
            }
        } catch (Exception ignored) { }
        return null;
    }

    private boolean identityHasRequestedAccess(
            SailPointContext context,
            Identity identity,
            ApprovalItem ai,
            String needle) throws GeneralException {
        if (isRoleBundle(ai)) {
            return identityHasRole(identity, needle);
        }
        return identityHasEntitlement(context, identity, ai.getApplication(), needle);
    }

    private boolean identityHasRole(Identity identity, String roleName) {
        if (identity == null || roleName == null || roleName.isEmpty()) return false;
        try {
            List<Bundle> roles = identity.getAssignedRoles();
            if (roles == null) return false;
            for (Bundle bundle : roles) {
                if (bundle != null && roleName.equals(bundle.getName())) return true;
            }
        } catch (Exception e) {
            log.debug("[Context] identityHasRole check failed login={} role={}", identity.getName(), roleName);
        }
        return false;
    }

    private static void putIfPresent(JSONObject target, String key, Object value) {
        if (value == null) return;
        String s = value.toString().trim();
        if (!s.isEmpty()) target.put(key, s);
    }

    private static void putSecondaryOwner(JSONObject target, Object secondaryOwner) {
        if (secondaryOwner == null) return;
        if (secondaryOwner instanceof Identity) {
            target.put("secondaryOwner", PluginUtil.displayName((Identity) secondaryOwner));
        } else {
            putIfPresent(target, "secondaryOwner", secondaryOwner);
        }
    }

    private static String stringFromMap(java.util.Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : "";
    }

    // ── helpers ───────────────────────────────────────────────────────────

    private String resolveIdentityRequestId(WorkItem workItem, Attributes wiAttrs) {
        try {
            if (workItem.getIdentityRequestId() != null) return workItem.getIdentityRequestId();
        } catch (Exception ignored) { }
        if (wiAttrs != null && wiAttrs.get("identityRequestId") != null) {
            return wiAttrs.get("identityRequestId").toString();
        }
        return "";
    }

    private Identity resolveBeneficiary(SailPointContext context, WorkItem workItem) throws GeneralException {
        String targetId = workItem.getTargetId();
        if (targetId == null || targetId.isEmpty()) return null;
        return context.getObject(Identity.class, targetId);
    }

    @SuppressWarnings("unchecked")
    private List<ApprovalItem> extractApprovalItems(WorkItem workItem) {
        List<ApprovalItem> items = new ArrayList<>();
        Attributes attrs = workItem.getAttributes();
        if (attrs == null) return items;
        Object approvalSetObj = attrs.get("approvalSet");
        if (approvalSetObj instanceof ApprovalSet) {
            ApprovalSet set = (ApprovalSet) approvalSetObj;
            if (set.getItems() != null) {
                for (Object o : set.getItems()) {
                    if (o instanceof ApprovalItem) items.add((ApprovalItem) o);
                }
            }
        }
        return items;
    }

    private JSONObject slimApprovalItem(ApprovalItem ai) {
        JSONObject item = new JSONObject();
        String app = ai.getApplication();
        String attr = ai.getName();
        String op = ai.getOperation() != null ? ai.getOperation().toString() : "Add";
        item.put("op", op);
        if (IIQ_APP.equalsIgnoreCase(app) && ASSIGNED_ROLES.equals(attr)) {
            item.put("type", "role");
            item.put("role", PluginUtil.stringVal(ai.getValue()) != null
                ? PluginUtil.stringVal(ai.getValue()) : ai.getDisplayValue());
        } else {
            item.put("type", "entitlement");
            item.put("app", app);
            item.put("attr", attr);
            String display = ai.getDisplayValue() != null ? ai.getDisplayValue() : PluginUtil.stringVal(ai.getValue());
            item.put("entitlement", display);
        }
        return item;
    }

    private boolean isRoleBundle(ApprovalItem ai) {
        return IIQ_APP.equalsIgnoreCase(ai.getApplication()) && ASSIGNED_ROLES.equals(ai.getName());
    }

    private void collectEntitlementsFromLink(Link link, String attrFilter, Set<String> out) {
        Attributes attrs = link.getAttributes();
        if (attrs == null || attrs.getMap() == null) return;
        for (Object keyObj : attrs.getMap().keySet()) {
            String key = keyObj != null ? keyObj.toString() : null;
            if (key == null) continue;
            if (attrFilter != null && !attrFilter.isEmpty() && !attrFilter.equals(key)) continue;
            Object val = attrs.get(key);
            if (val instanceof List) {
                for (Object v : (List<?>) val) addEntitlementValue(key, v, out);
            } else {
                addEntitlementValue(key, val, out);
            }
        }
    }

    private void addEntitlementValue(String attr, Object val, Set<String> out) {
        if (val == null) return;
        String s = val.toString().trim();
        if (!s.isEmpty()) out.add(attr + " = " + s);
    }

    private String formatEntitlement(String attr, String value) {
        if (value == null || value.isEmpty()) return null;
        return attr != null && !attr.isEmpty() ? attr + " = " + value : value;
    }

    private static boolean hasEntitlementNow(
            List<String> entitlementsOn, String attr, String value, String needle) {
        if (entitlementsOn == null || entitlementsOn.isEmpty()) return false;
        String exact = attr + " = " + value;
        for (String existing : entitlementsOn) {
            if (existing == null) continue;
            if (existing.equals(exact) || existing.contains(value)
                    || (needle != null && !needle.isEmpty() && existing.contains(needle))) {
                return true;
            }
        }
        return false;
    }

    private boolean identityHasEntitlement(
            SailPointContext context, Identity identity, String app, String needle) throws GeneralException {
        if (app == null || needle == null || needle.isEmpty()) return false;
        QueryOptions qo = new QueryOptions();
        qo.addFilter(Filter.and(
            Filter.eq("identity.id", identity.getId()),
            Filter.eq("application.name", app)
        ));
        qo.setResultLimit(50);
        Iterator<?> it = context.search(Link.class, qo);
        while (it.hasNext()) {
            Link link = (Link) it.next();
            Attributes attrs = link.getAttributes();
            if (attrs != null && attrs.toString().contains(needle)) return true;
        }
        return false;
    }

    private enum LineOutcome { APPROVED, DENIED, OPEN, OTHER }

    /**
     * Classify a request line using item approval state first (manager Rejected), then request completion.
     * IIQ uses CompletionStatus Success/Failure/Pending/Incomplete — not "Rejected" at request level.
     */
    private LineOutcome classifyRequestItemOutcome(IdentityRequestItem iri) {
        if (iri != null && iri.getApprovalState() != null) {
            String approval = iri.getApprovalState().toString().toLowerCase(Locale.ROOT);
            if (approval.contains("reject") || approval.contains("expired") || approval.contains("cancel")) {
                return LineOutcome.DENIED;
            }
        }
        IdentityRequest req = resolveIdentityRequest(iri);
        if (req == null || req.getCompletionStatus() == null) {
            return LineOutcome.OPEN;
        }
        String status = req.getCompletionStatus().toString().toLowerCase(Locale.ROOT);
        if (status.contains("success")) {
            return LineOutcome.APPROVED;
        }
        if (status.contains("failure")) {
            return LineOutcome.DENIED;
        }
        if (status.contains("pending") || status.contains("incomplete")) {
            return LineOutcome.OPEN;
        }
        return LineOutcome.OTHER;
    }

    private boolean isCompletedSuccess(IdentityRequestItem iri) {
        return classifyRequestItemOutcome(iri) == LineOutcome.APPROVED;
    }

    private IdentityRequest resolveIdentityRequest(IdentityRequestItem iri) {
        try {
            return iri.getIdentityRequest();
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isGrantOperation(String op) {
        return op != null && "Add".equalsIgnoreCase(op);
    }

    private static boolean isRemoveOperation(String op) {
        return op != null && ("Remove".equalsIgnoreCase(op) || "Delete".equalsIgnoreCase(op));
    }

    private JSONObject emptyHistory(JSONObject hist, String note) {
        hist.put("totalLines", 0);
        hist.put("approved", 0);
        hist.put("denied", 0);
        hist.put("open", 0);
        hist.put("other", 0);
        hist.put("approvalRateCompleted", JSONObject.NULL);
        if (note != null) hist.put("note", note);
        return hist;
    }

    private List<String> capList(Set<String> in, int cap) {
        List<String> list = new ArrayList<>(in);
        return list.subList(0, Math.min(cap, list.size()));
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max);
    }
}
