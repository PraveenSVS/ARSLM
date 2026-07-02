package com.iam.plugin.accessrequestassistant.service;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Approver-facing labels for LLM prompt rule codes (C1–C17, A1–A3).
 * Internal codes stay in logs; UI shows {@link PromptRule#label} and {@link PromptRule#rationale}.
 */
public final class LlmPromptRuleCatalog {

    public static final class PromptRule {
        public final String promptCode;
        public final String label;
        public final String rationale;
        /** Aligns with {@link AccessRequestRuleCatalog} when the signal is the same. */
        public final String javaRuleCode;

        PromptRule(String promptCode, String label, String rationale, String javaRuleCode) {
            this.promptCode = promptCode;
            this.label = label;
            this.rationale = rationale;
            this.javaRuleCode = javaRuleCode;
        }
    }

    private static final Map<String, PromptRule> BY_CODE = new LinkedHashMap<>();

    static {
        register("C1", "Identity inactive",
            "Identity is inactive in IIQ — confirm access is still appropriate before approving.",
            "BENEFICIARY_INACTIVE");
        register("C2", "Uncorrelated identity",
            "Uncorrelated (orphan) identity — ownership and accountability are unclear.",
            "BENEFICIARY_UNCORRELATED");
        register("C3", "Corp AD account disabled",
            "Corp AD account is not enabled for this identity — confirm access is still appropriate.",
            "REQUESTEE_AD_DISABLED");
        register("C4", "Role bundle inactive",
            "Requested business role bundle is disabled in catalog — may be sunset or deprecated.",
            "ROLE_BUNDLE_INACTIVE");
        register("C5", "Application account disabled",
            "Beneficiary's account on the target application is disabled — access may not be effective until the account is enabled.",
            "ACCOUNT_DISABLED_ON_APP");
        register("C6", "Application account locked",
            "Application account is locked — grant may not take effect until unlocked.",
            "ACCOUNT_LOCKED_ON_APP");
        register("C7", "Private group",
            "Private group membership requires explicit business justification.",
            "PRIVATE_GROUP");
        register("C8", "SOX access",
            "SOX-tagged access carries compliance scrutiny — approver should confirm need.",
            "SOX_CERTIFICATION_PERIOD");
        register("C9", "External access",
            "External-access entitlement — confirm third-party or off-network use is intended.",
            "EXTERNAL_ACCESS");
        register("C10", "Prerequisites not met",
            "Catalog prerequisite (reqGroups/reqRoles) is not met for this beneficiary.",
            "PREREQUISITE_NOT_SATISFIED");
        register("C11", "Elevated access",
            "Catalog marks this as elevated access — extra scrutiny warranted.",
            "CATALOG_ELEVATED_ACCESS");
        register("C12", "WMS account disabled",
            "WMS account is disabled — grant may not be effective.",
            "WMS_ACCOUNT_DISABLED");
        register("C13", "SOD violation accepted",
            "Requester proceeded after interactive SOD/policy violation — approver must consciously accept residual risk.",
            "SOD_VIOLATION_ACCEPTED");
        register("C14", "No peer precedent",
            "No peer under the same manager holds this access — weak team precedent (only when entitlement is established org-wide).",
            "NO_PEER_PATTERN");
        register("C15", "No request history",
            "No prior org requests for this entitlement/role in lookback — novel access pattern.",
            "NO_HISTORY_MATCH");
        register("C16", "Mostly denied history",
            "Org has 3+ completed requests with 2+ denials and more denials than approvals — elevated scrutiny.",
            "HISTORY_MOSTLY_DENIED");
        register("C17", "Recently lost access",
            "Beneficiary recently lost this access — confirm removal was intentional before re-granting.",
            "BENEFICIARY_PRIOR_ACCESS");
        register("C18", "Repeated denial for this user",
            "This beneficiary was denied 2 or more times for this access — confirm business need before approving.",
            "BENEFICIARY_PRIOR_DENIAL");
        register("A4", "Novel or limited context",
            "Thin request history or early org rollout — approve only with LOW confidence; confirm business requirement for new entitlements.",
            "NO_HISTORY_MATCH");
        register("A5", "Early org rollout",
            "Few identities hold this access org-wide — architects/early adopters expected; confirm documented requirement.",
            "NOVEL_ENTITLEMENT_IN_ORG");
        register("A1", "Strong approval signals",
            "Manager or peers hold this access, or org history is mostly approved — supports grant.",
            "HISTORY_MOSTLY_APPROVED");
        register("A2", "Likely reinstatement",
            "Beneficiary had this access before — likely reinstatement rather than net-new access.",
            "BENEFICIARY_PRIOR_ACCESS");
        register("A3", "No concerns flagged",
            "No review signals were flagged — conservative approve.",
            null);
    }

    private LlmPromptRuleCatalog() {
    }

    private static void register(String code, String label, String rationale, String javaRuleCode) {
        BY_CODE.put(code.toUpperCase(Locale.ROOT), new PromptRule(code, label, rationale, javaRuleCode));
    }

    public static PromptRule lookup(String promptCode) {
        if (promptCode == null || promptCode.trim().isEmpty()) {
            return null;
        }
        String key = promptCode.trim().toUpperCase(Locale.ROOT);
        PromptRule direct = BY_CODE.get(key);
        if (direct != null) {
            return direct;
        }
        int slash = key.indexOf('/');
        if (slash > 0) {
            return BY_CODE.get(key.substring(0, slash).trim());
        }
        return null;
    }
}
