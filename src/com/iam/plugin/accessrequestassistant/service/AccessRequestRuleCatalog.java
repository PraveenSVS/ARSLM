package com.iam.plugin.accessrequestassistant.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Documented rule catalog for {@link AccessRequestRuleEngine}.
 * Each rule is defensible at approver time — IIQ submit gates are intentionally excluded.
 */
public final class AccessRequestRuleCatalog {

    public static final String RULE_SET_VERSION = "1.3";

    public enum Category {
        REVIEW,
        POSITIVE,
        INFORMATIONAL
    }

    public static final class RuleDef {
        public final String code;
        public final int sortOrder;
        public final Category category;
        public final String condition;
        public final String rationale;
        public final String whyNotAtSubmit;

        RuleDef(String code, int sortOrder, Category category,
                String condition, String rationale, String whyNotAtSubmit) {
            this.code = code;
            this.sortOrder = sortOrder;
            this.category = category;
            this.condition = condition;
            this.rationale = rationale;
            this.whyNotAtSubmit = whyNotAtSubmit;
        }
    }

    private static final Map<String, RuleDef> BY_CODE = new LinkedHashMap<>();

    static {
        register(new RuleDef(
            "BENEFICIARY_INACTIVE", 5, Category.REVIEW,
            "beneficiary.inactive == true",
            "Identity is inactive in IIQ — confirm access is still appropriate before approving.",
            "Inactive identity status is not re-checked at approver work item load."));
        register(new RuleDef(
            "BENEFICIARY_UNCORRELATED", 6, Category.REVIEW,
            "beneficiary.correlated == false",
            "Uncorrelated (orphan) identity — ownership and accountability are unclear.",
            "Correlated status is not an approver-time submit gate."));
        register(new RuleDef(
            "REQUESTEE_AD_DISABLED", 7, Category.REVIEW,
            "beneficiary.isADAccountEnabled == false",
            "Corp AD account is not enabled for this identity — confirm access is still appropriate.",
            "AD account status is not re-shown on approver work items."));
        register(new RuleDef(
            "ROLE_BUNDLE_INACTIVE", 8, Category.REVIEW,
            "item.type=role and catalogPolicy.bundleDisabled == true",
            "Requested business role bundle is disabled in catalog — may be sunset or deprecated.",
            "Bundle disabled state may not block all request paths at submit."));
        register(new RuleDef(
            "ACCOUNT_DISABLED_ON_APP", 12, Category.REVIEW,
            "Add + accountContext.accountExists and linkDisabled == true",
            "Beneficiary's account on the target application is disabled — access may not be effective.",
            "Link disabled state is not always surfaced to approvers at decision time."));
        register(new RuleDef(
            "ACCOUNT_LOCKED_ON_APP", 14, Category.REVIEW,
            "Add + accountContext.linkLocked == true",
            "Application account is locked — grant may not take effect until unlocked.",
            "Link lock status is not evaluated when the request is submitted."));
        register(new RuleDef(
            "PRIVATE_GROUP", 15, Category.REVIEW,
            "catalogPolicy.privateGroup == true",
            "Private group membership requires explicit business justification.",
            "privateGroup is catalog metadata; IIQ does not block on this flag alone."));
        register(new RuleDef(
            "SOX_CERTIFICATION_PERIOD", 16, Category.REVIEW,
            "catalogPolicy.sox == true (certificationPeriod starts with SOX)",
            "SOX-tagged access carries compliance scrutiny — approver should confirm need.",
            "SOX certification period is not a submit-time rejection criterion."));
        register(new RuleDef(
            "EXTERNAL_ACCESS", 17, Category.REVIEW,
            "catalogPolicy.externalAccess == true",
            "External-access entitlement — confirm third-party or off-network use is intended.",
            "externalAccess flag is catalog metadata only."));
        register(new RuleDef(
            "PREREQUISITE_NOT_SATISFIED", 18, Category.REVIEW,
            "catalogPolicy.prerequisites defined and beneficiary does not satisfy expression",
            "Catalog prerequisite (reqGroups/reqRoles) is not met — Nike submit policy may not catch net-new requests.",
            "Prerequisite policy evaluates held access at submit; approver-time check targets the requested item."));
        register(new RuleDef(
            "CATALOG_ELEVATED_ACCESS", 19, Category.REVIEW,
            "catalogPolicy.iiqElevatedAccess == true",
            "Catalog marks this as elevated access — extra scrutiny warranted.",
            "Elevated flag is metadata; not always visible to approvers."));
        register(new RuleDef(
            "WMS_ACCOUNT_DISABLED", 20, Category.REVIEW,
            "Add + accountContext.wmsUserStatus == 0",
            "WMS account User_Status is disabled — grant may not be effective.",
            "WMS account status is not evaluated at approver decision time."));
        register(new RuleDef(
            "SOD_VIOLATION_ACCEPTED", 30, Category.REVIEW,
            "policyContext.violationCount > 0 on IdentityRequest",
            "Requester proceeded after interactive SOD/policy violation — approver must consciously accept residual risk.",
            "policyScheme=interactive allows override at submit; approver was not shown this at decision time."));
        register(new RuleDef(
            "NO_PEER_PATTERN", 40, Category.REVIEW,
            "peersSameManagerCount > 0 and peersWithEntitlementCount == 0 and orgHoldersCount >= 5",
            "No peer under the same manager holds this access — weak team precedent (established entitlement only).",
            "Peer pattern is not evaluated during catalog selection or API submit validation."));
        register(new RuleDef(
            "NOVEL_ENTITLEMENT_IN_ORG", 45, Category.INFORMATIONAL,
            "orgHoldersCount < 5 — early org rollout",
            "Few identities hold this access org-wide — manager/peer precedent not expected; confirm business requirement.",
            "Org adoption count is approver-context only."));
        register(new RuleDef(
            "NO_HISTORY_MATCH", 50, Category.REVIEW,
            "entitlementHistory.totalLines == 0 in lookback window",
            "No prior org requests for this entitlement/role in lookback — novel access pattern.",
            "Request history is not checked when the request is submitted."));
        register(new RuleDef(
            "HISTORY_MOSTLY_DENIED", 60, Category.REVIEW,
            "completed>=3 and denied>=2 and denied > approved",
            "Org has enough completed requests with a denial pattern — elevated scrutiny.",
            "Historical approve/deny rates are not submit gates."));
        register(new RuleDef(
            "BENEFICIARY_PRIOR_DENIAL", 65, Category.REVIEW,
            "beneficiaryRequestDenied >= 2 for same access in lookback",
            "This beneficiary was denied 2+ times for this access — confirm business need.",
            "Per-user denial count is approver-context only."));
        register(new RuleDef(
            "BENEFICIARY_PRIOR_ACCESS", 70, Category.REVIEW,
            "Add + not currently entitled + recentlyLostAccess (priorAccessSignal=recently_lost)",
            "User recently lost this access — confirm removal was intentional before re-granting.",
            "Prior-access timeline is not evaluated at submit."));
        register(new RuleDef(
            "MANAGER_HAS_ENTITLEMENT", 80, Category.POSITIVE,
            "orgContext.managerHasEntitlement == true",
            "Direct manager already holds the access — strong job-function precedent.",
            "Manager entitlement check is approver-context only."));
        register(new RuleDef(
            "STRONG_PEER_PATTERN", 90, Category.POSITIVE,
            "peersWithEntitlementCount >= 3",
            "Three or more peers under the same manager have this access — strong team norm.",
            "Peer counts are not submit-time validation."));
        register(new RuleDef(
            "HISTORY_MOSTLY_APPROVED", 100, Category.POSITIVE,
            "approved > 0 and denied == 0 in entitlement history",
            "Clean approval history for this access in the org — supports grant.",
            "History is not used to auto-approve at submit."));
        register(new RuleDef(
            "BENEFICIARY_PRIOR_ACCESS", 110, Category.POSITIVE,
            "Add + not currently entitled + previouslyHadAccess + not recentlyLost (reinstatement)",
            "Beneficiary had this access before — likely reinstatement rather than net-new access.",
            "Reinstatement signal is approver-time only."));
        register(new RuleDef(
            "CATALOG_DYNAMIC_GROUP", 115, Category.INFORMATIONAL,
            "catalogPolicy.dynamicGroup == true",
            "Dynamic group — membership may be auto-maintained.",
            "dynamicGroup is catalog metadata only."));
        register(new RuleDef(
            "CATALOG_SUNSET_CONFIGURED", 118, Category.INFORMATIONAL,
            "approvalContext.catalogSunsetDays > 0 or catalogPolicy.catalogSunsetDays > 0",
            "Catalog defines a maximum assignment duration — confirm end date aligns with sunset policy.",
            "Sunset may be enforced at submit; this informs approver of catalog limit."));
        register(new RuleDef(
            "APPROVAL_SECONDARY_OWNER_SCHEME", 119, Category.INFORMATIONAL,
            "approvalScheme is ManagerPrimarySecondary or PrimarySecondary",
            "Catalog expects owner plus secondary owner approval steps.",
            "Secondary-owner routing is not summarized on the work item."));
        register(new RuleDef(
            "MANAGER_AND_OWNER_SCHEME", 120, Category.INFORMATIONAL,
            "approvalContext.approvalScheme is ManagerAndOwner",
            "Catalog requires manager and entitlement owner approval — conscious dual sign-off expected.",
            "Approval scheme is metadata; approver may not see full routing context."));
        register(new RuleDef(
            "REQUESTEE_EXTERNAL", 121, Category.INFORMATIONAL,
            "beneficiary.identityType == External",
            "External identity population — confirm access is appropriate for third-party user.",
            "Catalog filtering at submit does not explain population to approvers."));
        register(new RuleDef(
            "REQUESTEE_TEMPORARY_WORKER", 122, Category.INFORMATIONAL,
            "beneficiary.userType == Temporary Worker",
            "Temporary worker population — often limited to WMS applications.",
            "Population context is not shown on approver work items."));
        register(new RuleDef(
            "ROLE_WMS_PROFILE", 123, Category.INFORMATIONAL,
            "catalogPolicy.roleType == wmosProfile",
            "WMOS profile role — warehouse operational access.",
            "Role type is not surfaced on approver work items."));
        register(new RuleDef(
            "LINK_PRIVILEGED", 124, Category.INFORMATIONAL,
            "Add + accountContext.linkPrivileged == true",
            "Beneficiary already has a privileged account on this application.",
            "Privileged link flag is not re-evaluated at approver decision time."));
        register(new RuleDef(
            "ACCOUNT_MISSING_ON_APP", 125, Category.INFORMATIONAL,
            "Add + entitlement + accountContext.accountExists == false",
            "No account on target application yet — provisioning may create net-new account.",
            "Missing account is not always flagged to approvers."));
        register(new RuleDef(
            "TEMPORARY_ASSIGNMENT", 126, Category.INFORMATIONAL,
            "approvalContext.temporaryAssignment == true (end date set)",
            "Time-bound assignment — approver should confirm duration and business justification.",
            "Sunset is applied at submit; temporary flag informs approver, does not block."));
    }

    private AccessRequestRuleCatalog() {
    }

    private static void register(RuleDef def) {
        BY_CODE.put(def.code, def);
    }

    public static RuleDef get(String code) {
        return BY_CODE.get(code);
    }

    public static int sortOrder(String code) {
        RuleDef def = BY_CODE.get(code);
        return def != null ? def.sortOrder : 999;
    }

    /** Stable order for rulesFired[] — same combination always serializes identically. */
    public static List<String> sortCodes(List<String> codes) {
        List<String> sorted = new ArrayList<>(codes);
        Collections.sort(sorted, Comparator.comparingInt(AccessRequestRuleCatalog::sortOrder));
        return sorted;
    }
}
