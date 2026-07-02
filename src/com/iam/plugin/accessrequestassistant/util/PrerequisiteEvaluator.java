package com.iam.plugin.accessrequestassistant.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lightweight check for Nike catalog prerequisite expressions (reqGroups / reqRoles).
 * Supports flat AND / OR of {@code (Ent=app~attr@value)} and {@code (Bundle=name)} clauses.
 */
public final class PrerequisiteEvaluator {

    private static final Pattern CLAUSE =
        Pattern.compile("\\((Ent|Bundle)=([^)]+)\\)", Pattern.CASE_INSENSITIVE);

    private PrerequisiteEvaluator() {
    }

    public static boolean hasPrerequisites(String expression) {
        return expression != null && !expression.trim().isEmpty();
    }

    public static boolean satisfied(String expression, List<String> entitlements, List<String> roles) {
        if (!hasPrerequisites(expression)) {
            return true;
        }
        List<String> clauses = extractClauses(expression);
        if (clauses.isEmpty()) {
            return true;
        }
        boolean orLogic = expression.toUpperCase(Locale.ROOT).contains(" OR ");
        List<String> ents = entitlements != null ? entitlements : new ArrayList<>();
        List<String> roleNames = roles != null ? roles : new ArrayList<>();

        if (orLogic) {
            for (String clause : clauses) {
                if (clauseSatisfied(clause, ents, roleNames)) {
                    return true;
                }
            }
            return false;
        }
        for (String clause : clauses) {
            if (!clauseSatisfied(clause, ents, roleNames)) {
                return false;
            }
        }
        return true;
    }

    private static List<String> extractClauses(String expression) {
        List<String> out = new ArrayList<>();
        Matcher m = CLAUSE.matcher(expression);
        while (m.find()) {
            out.add(m.group(1) + "=" + m.group(2).trim());
        }
        return out;
    }

    private static boolean clauseSatisfied(String clause, List<String> entitlements, List<String> roles) {
        if (clause == null) return false;
        String normalized = clause.trim();
        if (normalized.regionMatches(true, 0, "Ent=", 0, 4)) {
            return entitlementHeld(normalized.substring(4).trim(), entitlements);
        }
        if (normalized.regionMatches(true, 0, "Bundle=", 0, 7)) {
            String roleName = normalized.substring(7).trim();
            for (String assigned : roles) {
                if (roleName.equalsIgnoreCase(assigned)) {
                    return true;
                }
            }
            return false;
        }
        return false;
    }

    private static boolean entitlementHeld(String spec, List<String> entitlements) {
        int attIdx = spec.indexOf('~');
        int valIdx = spec.indexOf('@');
        if (attIdx < 0 || valIdx < 0 || valIdx <= attIdx) {
            return false;
        }
        String value = spec.substring(valIdx + 1).trim();
        if (value.isEmpty()) return false;
        for (String ent : entitlements) {
            if (ent != null && (value.equalsIgnoreCase(ent) || ent.equalsIgnoreCase(value))) {
                return true;
            }
        }
        return false;
    }
}
