package com.iam.plugin.accessrequestassistant.util;

import org.json.JSONArray;

public final class PluginUtil {

    private PluginUtil() {}

    public static boolean isTruthy(Object val) {
        if (val == null) return false;
        if (val instanceof Boolean) return (Boolean) val;
        if (val instanceof Number) return ((Number) val).intValue() != 0;
        String s = val.toString().trim().toLowerCase();
        return !s.isEmpty() && !"0".equals(s) && !"false".equals(s) && !"no".equals(s);
    }

    public static JSONArray stringListToJson(java.util.Collection<String> values) {
        JSONArray arr = new JSONArray();
        if (values == null) return arr;
        for (String v : values) {
            if (v != null && !v.isEmpty()) arr.put(v);
        }
        return arr;
    }

    public static String stringVal(Object value) {
        return value == null ? null : String.valueOf(value).trim();
    }

    public static String displayName(sailpoint.object.Identity identity) {
        if (identity == null) return "Unknown";
        if (identity.getDisplayName() != null && !identity.getDisplayName().isEmpty()) {
            return identity.getDisplayName();
        }
        return identity.getName();
    }
}
