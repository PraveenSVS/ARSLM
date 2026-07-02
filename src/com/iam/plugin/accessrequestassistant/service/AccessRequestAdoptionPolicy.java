package com.iam.plugin.accessrequestassistant.service;

import org.json.JSONObject;

/**
 * Org-wide adoption thresholds — new entitlements (e.g. Databricks rollout) may have few holders
 * and no manager/peer precedent; that is expected, not a peer-pattern failure.
 */
public final class AccessRequestAdoptionPolicy {

    /** Holders scanned before capping (performance guard). */
    public static final int ORG_HOLDERS_SCAN_CAP = 30;
    /** Below this count, entitlement is treated as early org rollout. */
    public static final int MIN_ORG_HOLDERS_FOR_PEER_PATTERN = 5;

    private AccessRequestAdoptionPolicy() {
    }

    public static boolean isNovelEntitlementInOrg(JSONObject orgContext) {
        if (orgContext == null || !orgContext.has("orgHoldersCount")) {
            return false;
        }
        if (orgContext.optBoolean("orgHoldersCountCapped", false)
                && orgContext.optInt("orgHoldersCount", 0) >= ORG_HOLDERS_SCAN_CAP) {
            return false;
        }
        return orgContext.optInt("orgHoldersCount", 0) < MIN_ORG_HOLDERS_FOR_PEER_PATTERN;
    }

    public static void applyAdoptionFlags(JSONObject llm, JSONObject org) {
        if (org == null) {
            return;
        }
        if (org.has("orgHoldersCount")) {
            llm.put("orgHoldersCount", org.optInt("orgHoldersCount", 0));
            if (org.optBoolean("orgHoldersCountCapped", false)) {
                llm.put("orgHoldersCountCapped", true);
            }
        }
        if (isNovelEntitlementInOrg(org)) {
            llm.put("novelEntitlementInOrg", true);
        }
    }

    public static boolean peerPatternReviewApplicable(JSONObject org) {
        return !isNovelEntitlementInOrg(org);
    }

    public static void enrichDataQuality(JSONObject dq, JSONObject accessContext) {
        JSONObject org = accessContext.optJSONObject("orgContext");
        if (!isNovelEntitlementInOrg(org)) {
            return;
        }
        int holders = org.optInt("orgHoldersCount", 0);
        dq.put("novelEntitlementInOrg", true);
        dq.put("orgHoldersCount", holders);
        String adoptionNote = "New entitlement in org (~" + holders + " holder"
            + (holders == 1 ? "" : "s")
            + ") — manager/peer precedent not expected yet; confirm documented business requirement.";
        String existing = dq.optString("note", "").trim();
        dq.put("note", existing.isEmpty() ? adoptionNote : existing + " " + adoptionNote);
        if ("established".equals(dq.optString("richness", ""))) {
            dq.put("richness", "limited");
        }
    }
}
