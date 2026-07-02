package com.iam.plugin.accessrequestassistant.service;

import org.json.JSONObject;

/**
 * Thresholds for org/beneficiary request history — avoid strong conclusions from a single
 * denial or thin samples. Used by LLM flags, Java fallback rules, and data-quality metadata.
 */
public final class AccessRequestHistoryPolicy {

    /** Completed (approved+denied) org lines before org-wide approve/deny patterns apply. */
    public static final int MIN_ORG_COMPLETED_FOR_PATTERN = 3;
    /** Minimum org denials before {@code historyMostlyDenied}. */
    public static final int MIN_ORG_DENIALS_FOR_MOSTLY_DENIED = 2;
    /** Minimum org approvals before {@code historyMostlyApproved}. */
    public static final int MIN_ORG_APPROVALS_FOR_MOSTLY_APPROVED = 2;
    /** Beneficiary denials for same access before repeat-denial review (one denial is not enough). */
    public static final int MIN_BENEFICIARY_DENIALS_FOR_REVIEW = 2;

    public enum Richness { NOVEL, LIMITED, ESTABLISHED }

    private AccessRequestHistoryPolicy() {
    }

    public static void applyHistoryFlags(JSONObject llm, JSONObject hist, JSONObject timeline) {
        int beneficiaryDenied = timeline != null ? timeline.optInt("beneficiaryRequestDenied", 0) : 0;
        int beneficiaryApproved = timeline != null ? timeline.optInt("beneficiaryRequestApproved", 0) : 0;

        if (beneficiaryDenied >= MIN_BENEFICIARY_DENIALS_FOR_REVIEW) {
            llm.put("beneficiaryDeniedForAccess", true);
        } else if (beneficiaryDenied == 1) {
            llm.put("beneficiaryDeniedOnce", true);
        }
        if (beneficiaryApproved > 0) {
            llm.put("beneficiaryApprovedForAccess", beneficiaryApproved);
        }

        if (hist == null) {
            llm.put("noRequestHistory", true);
            llm.put("novelAccess", true);
            return;
        }

        int total = hist.optInt("totalLines", 0);
        int approved = hist.optInt("approved", 0);
        int denied = hist.optInt("denied", 0);
        int open = hist.optInt("open", 0);
        int other = hist.optInt("other", 0);
        int completed = approved + denied;

        llm.put("orgHistoryCompleted", completed);
        llm.put("orgHistoryPending", open + other);

        if (total == 0) {
            llm.put("noRequestHistory", true);
            llm.put("novelAccess", true);
            return;
        }

        if (completed < MIN_ORG_COMPLETED_FOR_PATTERN) {
            llm.put("limitedOrgHistory", true);
            llm.put("novelAccess", true);
        }

        if (completed >= MIN_ORG_COMPLETED_FOR_PATTERN
                && denied >= MIN_ORG_DENIALS_FOR_MOSTLY_DENIED
                && denied > approved) {
            llm.put("historyMostlyDenied", true);
        }

        if (completed >= MIN_ORG_COMPLETED_FOR_PATTERN
                && approved >= MIN_ORG_APPROVALS_FOR_MOSTLY_APPROVED
                && denied == 0
                && beneficiaryDenied < MIN_BENEFICIARY_DENIALS_FOR_REVIEW) {
            llm.put("historyMostlyApproved", true);
        }
    }

    public static Richness richness(JSONObject hist) {
        if (hist == null || hist.optInt("totalLines", 0) == 0) {
            return Richness.NOVEL;
        }
        int completed = hist.optInt("approved", 0) + hist.optInt("denied", 0);
        if (completed >= MIN_ORG_COMPLETED_FOR_PATTERN) {
            return Richness.ESTABLISHED;
        }
        return Richness.LIMITED;
    }

    public static JSONObject buildDataQuality(JSONObject accessContext) {
        JSONObject hist = accessContext.optJSONObject("entitlementHistory");
        JSONObject timeline = accessContext.optJSONObject("beneficiaryAccessTimeline");
        JSONObject dq = new JSONObject();

        int completed = hist != null ? hist.optInt("approved", 0) + hist.optInt("denied", 0) : 0;
        int pending = hist != null ? hist.optInt("open", 0) + hist.optInt("other", 0) : 0;
        int benDenied = timeline != null ? timeline.optInt("beneficiaryRequestDenied", 0) : 0;
        int benApproved = timeline != null ? timeline.optInt("beneficiaryRequestApproved", 0) : 0;

        Richness r = richness(hist);
        dq.put("richness", r.name().toLowerCase());
        dq.put("orgHistoryCompleted", completed);
        dq.put("orgHistoryPending", pending);
        dq.put("beneficiaryDenied", benDenied);
        dq.put("beneficiaryApproved", benApproved);
        dq.put("note", dataQualityNote(r, completed, pending, benDenied));
        AccessRequestAdoptionPolicy.enrichDataQuality(dq, accessContext);
        return dq;
    }

    private static String dataQualityNote(Richness r, int completed, int pending, int benDenied) {
        if (r == Richness.NOVEL) {
            return "Novel access — no completed org request history; use LOW confidence on approve.";
        }
        if (r == Richness.LIMITED) {
            String base = "Limited org history (" + completed + " completed";
            if (pending > 0) base += ", " + pending + " pending";
            base += ") — not enough data for strong org-wide approve/deny patterns.";
            if (benDenied == 1) {
                base += " One prior denial for this user is noted but not treated as a pattern.";
            }
            return base;
        }
        if (benDenied == 1) {
            return "Established org history; one prior denial for this user is informational only.";
        }
        return "Established org history (" + completed + " completed requests in lookback).";
    }

    /** Cap advisory confidence when history is thin; never upgrade above LLM level. */
    public static void applyConfidenceCap(JSONObject decision, JSONObject accessContext) {
        JSONObject dq = buildDataQuality(accessContext);
        decision.put("dataQuality", dq);

        Richness r = Richness.valueOf(dq.optString("richness", "novel").toUpperCase());
        String rec = decision.optString("recommendation", "");
        String level = decision.optString("confidenceLevel", "MEDIUM");
        boolean novelEntitlement = dq.optBoolean("novelEntitlementInOrg", false);

        if (r == Richness.NOVEL || r == Richness.LIMITED || novelEntitlement) {
            if ("approve".equals(rec)) {
                level = capLevel(level, "LOW");
            } else if ("needs_manual_review".equals(rec) && (r == Richness.NOVEL || novelEntitlement)) {
                level = capLevel(level, "MEDIUM");
            }
        }

        decision.put("confidenceLevel", level);
        decision.put("confidence", confidenceToNumeric(level, rec));
    }

    private static String capLevel(String current, String cap) {
        int cur = levelRank(current);
        int max = levelRank(cap);
        return cur > max ? cap : current;
    }

    private static int levelRank(String level) {
        if (level == null) return 1;
        switch (level.trim().toUpperCase()) {
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW":
            default: return 1;
        }
    }

    private static double confidenceToNumeric(String level, String recommendation) {
        if (level == null) level = "MEDIUM";
        switch (level.trim().toUpperCase()) {
            case "HIGH": return "approve".equals(recommendation) ? 0.72 : 0.68;
            case "LOW": return 0.62;
            case "MEDIUM":
            default: return "approve".equals(recommendation) ? 0.65 : 0.68;
        }
    }
}
