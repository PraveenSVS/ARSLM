package com.iam.plugin.accessrequestassistant.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import com.iam.plugin.accessrequestassistant.util.PrerequisiteEvaluator;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Deterministic approver-assist rules.
 * Same context JSON in → same decision JSON out (rules, confidence, recommendation).
 * Signals IIQ does not evaluate at submit time — see {@link AccessRequestRuleCatalog}.
 */
public class AccessRequestRuleEngine {

    private static final Logger log = LogManager.getLogger(AccessRequestRuleEngine.class);

    public JSONObject evaluate(JSONObject context) {
        String workItemId = context.optString("workItemId", "?");
        log.info("[Rules] evaluate start workItemId={} ruleSetVersion={}",
            workItemId, AccessRequestRuleCatalog.RULE_SET_VERSION);

        Set<String> firedSet = new LinkedHashSet<>();
        boolean review = false;
        boolean positive = false;

        JSONObject item = context.optJSONObject("item");
        JSONObject ben = context.optJSONObject("beneficiary");
        JSONObject org = context.optJSONObject("orgContext");
        JSONObject hist = context.optJSONObject("entitlementHistory");
        JSONObject priorAccess = context.optJSONObject("beneficiaryAccessTimeline");
        JSONObject catalog = context.optJSONObject("catalogPolicy");
        JSONObject approval = context.optJSONObject("approvalContext");
        JSONObject policyCtx = context.optJSONObject("policyContext");
        JSONObject account = context.optJSONObject("accountContext");

        boolean requestingAdd = item == null
            || !"Remove".equalsIgnoreCase(item.optString("op", "Add"));
        boolean entitlementItem = item == null
            || !"role".equalsIgnoreCase(item.optString("type", "entitlement"));

        if (ben != null && ben.optBoolean("inactive", false)) {
            fire(firedSet, "BENEFICIARY_INACTIVE", workItemId);
            review = true;
        }
        if (ben != null && ben.has("correlated") && !ben.optBoolean("correlated", true)) {
            fire(firedSet, "BENEFICIARY_UNCORRELATED", workItemId);
            review = true;
        }
        if (ben != null && ben.has("isADAccountEnabled") && !ben.optBoolean("isADAccountEnabled", true)) {
            fire(firedSet, "REQUESTEE_AD_DISABLED", workItemId);
            review = true;
        }
        if (ben != null && "External".equalsIgnoreCase(ben.optString("identityType", ""))) {
            fire(firedSet, "REQUESTEE_EXTERNAL", workItemId);
        }
        if (ben != null && "Temporary Worker".equalsIgnoreCase(ben.optString("userType", ""))) {
            fire(firedSet, "REQUESTEE_TEMPORARY_WORKER", workItemId);
        }

        if (item != null && "role".equalsIgnoreCase(item.optString("type"))
                && catalog != null && catalog.optBoolean("bundleDisabled", false)) {
            fire(firedSet, "ROLE_BUNDLE_INACTIVE", workItemId);
            review = true;
        }

        if (requestingAdd && account != null && account.optBoolean("applicable", true)) {
            boolean accountExists = account.optBoolean("accountExists", false);
            if (accountExists && account.optBoolean("linkDisabled", false)) {
                fire(firedSet, "ACCOUNT_DISABLED_ON_APP", workItemId);
                review = true;
            }
            if (account.optBoolean("linkLocked", false)) {
                fire(firedSet, "ACCOUNT_LOCKED_ON_APP", workItemId);
                review = true;
            }
            if (account.optInt("wmsUserStatus", 1) == 0) {
                fire(firedSet, "WMS_ACCOUNT_DISABLED", workItemId);
                review = true;
            }
            if (account.optBoolean("linkPrivileged", false)) {
                fire(firedSet, "LINK_PRIVILEGED", workItemId);
            }
            if (entitlementItem && !accountExists) {
                fire(firedSet, "ACCOUNT_MISSING_ON_APP", workItemId);
            }
        }

        if (catalog != null) {
            if (catalog.optBoolean("privateGroup", false)) {
                fire(firedSet, "PRIVATE_GROUP", workItemId);
                review = true;
            }
            if (catalog.optBoolean("sox", false)) {
                fire(firedSet, "SOX_CERTIFICATION_PERIOD", workItemId);
                review = true;
            }
            if (catalog.optBoolean("externalAccess", false)) {
                fire(firedSet, "EXTERNAL_ACCESS", workItemId);
                review = true;
            }
            if (catalog.optBoolean("iiqElevatedAccess", false)) {
                fire(firedSet, "CATALOG_ELEVATED_ACCESS", workItemId);
                review = true;
            }
            if (catalog.optBoolean("dynamicGroup", false)) {
                fire(firedSet, "CATALOG_DYNAMIC_GROUP", workItemId);
            }
            if ("wmosProfile".equalsIgnoreCase(catalog.optString("roleType", ""))) {
                fire(firedSet, "ROLE_WMS_PROFILE", workItemId);
            }
            String prerequisites = catalog.optString("prerequisites", "");
            if (PrerequisiteEvaluator.hasPrerequisites(prerequisites)
                    && !PrerequisiteEvaluator.satisfied(
                        prerequisites,
                        jsonStringList(context.optJSONArray("entitlementsOn")),
                        jsonStringList(ben != null ? ben.optJSONArray("assignedRoles") : null))) {
                fire(firedSet, "PREREQUISITE_NOT_SATISFIED", workItemId);
                review = true;
            }
        }

        int catalogSunset = catalogSunsetDays(catalog, approval);
        if (catalogSunset > 0) {
            fire(firedSet, "CATALOG_SUNSET_CONFIGURED", workItemId);
        }

        if (approval != null) {
            String scheme = approval.optString("approvalScheme", "");
            if (isManagerAndOwnerScheme(scheme)) {
                fire(firedSet, "MANAGER_AND_OWNER_SCHEME", workItemId);
            } else if (isSecondaryOwnerScheme(scheme)) {
                fire(firedSet, "APPROVAL_SECONDARY_OWNER_SCHEME", workItemId);
            }
        }

        if (policyCtx != null && policyCtx.optInt("violationCount", 0) > 0) {
            fire(firedSet, "SOD_VIOLATION_ACCEPTED", workItemId);
            review = true;
        }

        if (approval != null && approval.optBoolean("temporaryAssignment", false)) {
            fire(firedSet, "TEMPORARY_ASSIGNMENT", workItemId);
        }

        if (org != null) {
            int peerWith = org.optInt("peersWithEntitlementCount", 0);
            int peerTotal = org.optInt("peersSameManagerCount", 0);
            if (peerTotal > 0 && peerWith == 0) {
                if (AccessRequestAdoptionPolicy.peerPatternReviewApplicable(org)) {
                    fire(firedSet, "NO_PEER_PATTERN", workItemId);
                    review = true;
                } else {
                    fire(firedSet, "NOVEL_ENTITLEMENT_IN_ORG", workItemId);
                }
            }
            if (org.optBoolean("managerHasEntitlement", false)) {
                fire(firedSet, "MANAGER_HAS_ENTITLEMENT", workItemId);
                positive = true;
            }
            if (peerTotal > 0 && peerWith >= 3) {
                fire(firedSet, "STRONG_PEER_PATTERN", workItemId);
                positive = true;
            }
        }

        if (hist != null) {
            int approved = hist.optInt("approved", 0);
            int denied = hist.optInt("denied", 0);
            int completed = approved + denied;
            JSONObject timeline = context.optJSONObject("beneficiaryAccessTimeline");
            int benDenied = timeline != null ? timeline.optInt("beneficiaryRequestDenied", 0) : 0;

            if (completed >= AccessRequestHistoryPolicy.MIN_ORG_COMPLETED_FOR_PATTERN) {
                if (denied >= AccessRequestHistoryPolicy.MIN_ORG_DENIALS_FOR_MOSTLY_DENIED
                        && denied > approved) {
                    fire(firedSet, "HISTORY_MOSTLY_DENIED", workItemId);
                    review = true;
                } else if (approved >= AccessRequestHistoryPolicy.MIN_ORG_APPROVALS_FOR_MOSTLY_APPROVED
                        && denied == 0
                        && benDenied < AccessRequestHistoryPolicy.MIN_BENEFICIARY_DENIALS_FOR_REVIEW) {
                    fire(firedSet, "HISTORY_MOSTLY_APPROVED", workItemId);
                    positive = true;
                }
            }
        }

        if (priorAccess != null) {
            int benDenied = priorAccess.optInt("beneficiaryRequestDenied", 0);
            if (benDenied >= AccessRequestHistoryPolicy.MIN_BENEFICIARY_DENIALS_FOR_REVIEW) {
                fire(firedSet, "BENEFICIARY_PRIOR_DENIAL", workItemId);
                review = true;
            }
        }

        String priorAccessSignal = null;
        if (requestingAdd && priorAccess != null && !priorAccess.optBoolean("currentlyHasAccess", false)) {
            if (priorAccess.optBoolean("recentlyLostAccess", false)) {
                fire(firedSet, "BENEFICIARY_PRIOR_ACCESS", workItemId);
                priorAccessSignal = "recently_lost";
                review = true;
            } else if (priorAccess.optBoolean("previouslyHadAccess", false)) {
                fire(firedSet, "BENEFICIARY_PRIOR_ACCESS", workItemId);
                priorAccessSignal = "reinstatement";
                positive = true;
            }
        }

        List<String> sortedRules = AccessRequestRuleCatalog.sortCodes(new ArrayList<>(firedSet));
        JSONArray rulesFired = new JSONArray();
        for (String code : sortedRules) {
            rulesFired.put(code);
        }

        String recommendation;
        double confidence;
        if (review) {
            recommendation = "needs_manual_review";
            confidence = positive ? 0.62 : 0.68;
        } else if (positive) {
            recommendation = "approve";
            confidence = 0.72;
        } else {
            recommendation = "approve";
            confidence = 0.62;
        }

        JSONObject decision = new JSONObject();
        decision.put("recommendation", recommendation);
        decision.put("confidence", confidence);
        decision.put("rulesFired", rulesFired);
        decision.put("ruleSetVersion", AccessRequestRuleCatalog.RULE_SET_VERSION);
        decision.put("source", "deterministic_rules");
        decision.put("decisionBasis", buildDecisionBasis(review, positive, sortedRules));
        decision.put("ruleDetails", buildRuleDetails(sortedRules, priorAccessSignal));
        if (priorAccessSignal != null) {
            decision.put("priorAccessSignal", priorAccessSignal);
        }

        log.info("[Rules] evaluate done workItemId={} recommendation={} confidence={} rulesFired={}",
            workItemId, recommendation, confidence, rulesFired);
        return decision;
    }

    private static int catalogSunsetDays(JSONObject catalog, JSONObject approval) {
        int days = 0;
        if (catalog != null) {
            days = Math.max(days, catalog.optInt("catalogSunsetDays", 0));
        }
        if (approval != null) {
            days = Math.max(days, approval.optInt("catalogSunsetDays", 0));
        }
        return days;
    }

    private static boolean isSecondaryOwnerScheme(String scheme) {
        if (scheme == null || scheme.isEmpty()) return false;
        String normalized = scheme.replaceAll("[\\s_-]", "").toLowerCase();
        return "managerprimarysecondary".equals(normalized) || "primarysecondary".equals(normalized);
    }

    private static List<String> jsonStringList(JSONArray arr) {
        List<String> out = new ArrayList<>();
        if (arr == null) return out;
        for (int i = 0; i < arr.length(); i++) {
            String s = arr.optString(i, "").trim();
            if (!s.isEmpty()) out.add(s);
        }
        return out;
    }

    private static boolean isManagerAndOwnerScheme(String scheme) {
        if (scheme == null || scheme.isEmpty()) return false;
        String normalized = scheme.replaceAll("[\\s_-]", "").toLowerCase();
        return "managerandowner".equals(normalized);
    }

    private static JSONArray buildRuleDetails(List<String> sortedRules, String priorAccessSignal) {
        JSONArray details = new JSONArray();
        for (String code : sortedRules) {
            AccessRequestRuleCatalog.RuleDef def = AccessRequestRuleCatalog.get(code);
            if (def == null) continue;
            JSONObject row = new JSONObject();
            row.put("code", def.code);
            row.put("category", def.category.name().toLowerCase());
            row.put("condition", def.condition);
            row.put("rationale", def.rationale);
            row.put("whyNotAtSubmit", def.whyNotAtSubmit);
            if ("BENEFICIARY_PRIOR_ACCESS".equals(code) && priorAccessSignal != null) {
                row.put("priorAccessSignal", priorAccessSignal);
            }
            details.put(row);
        }
        return details;
    }

    private static String buildDecisionBasis(boolean review, boolean positive, List<String> sortedRules) {
        if (sortedRules.isEmpty()) {
            return "No review or positive signals fired — conservative low-confidence approve (nothing notable in context).";
        }
        if (review && positive) {
            return "Mixed signals: review rules fired with offsetting positive signals — needs_manual_review at confidence "
                + (positive ? "0.62" : "0.68") + ". Rules: " + String.join(", ", sortedRules);
        }
        if (review) {
            return "One or more review signals fired — needs_manual_review. Rules: " + String.join(", ", sortedRules);
        }
        return "Positive signals without review signals — approve. Rules: " + String.join(", ", sortedRules);
    }

    private static void fire(Set<String> firedSet, String code, String workItemId) {
        if (firedSet.add(code)) {
            log.debug("[Rules] fired {} workItemId={}", code, workItemId);
        }
    }
}
