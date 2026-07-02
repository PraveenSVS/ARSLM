package com.iam.plugin.accessrequestassistant.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * HTTP client for Databricks Model Serving (explain-only access-request endpoint).
 */
public class DatabricksService {

    private static final Logger log = LogManager.getLogger(DatabricksService.class);

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int SOCKET_TIMEOUT_MS  = 90_000;

    private final String endpointUrl;
    private final String token;

    public DatabricksService(String databricksHost, String databricksEndpoint, String databricksToken) {
        if (databricksHost != null && databricksHost.endsWith("/")) {
            databricksHost = databricksHost.substring(0, databricksHost.length() - 1);
        }
        this.endpointUrl = databricksHost + "/serving-endpoints/" + databricksEndpoint + "/invocations";
        this.token = databricksToken;
        log.info("[Databricks] client ready endpoint={}", this.endpointUrl);
    }

    public String chatCompletion(String systemPrompt, String userMessage, int maxTokens) throws IOException {
        long t0 = System.currentTimeMillis();
        JSONObject requestBody = new JSONObject();
        requestBody.put("max_tokens", maxTokens);

        JSONArray messages = new JSONArray();
        messages.put(new JSONObject().put("role", "system").put("content", systemPrompt));
        messages.put(new JSONObject().put("role", "user").put("content", userMessage));
        requestBody.put("messages", messages);

        int payloadChars = requestBody.toString().length();
        log.info("[Databricks] request start endpoint={} maxTokens={} systemChars={} userChars={} payloadChars={}",
            endpointUrl, maxTokens, systemPrompt.length(), userMessage.length(), payloadChars);
        log.debug("[Databricks] request body:\n{}", requestBody);

        RequestConfig config = RequestConfig.custom()
            .setConnectTimeout(CONNECT_TIMEOUT_MS)
            .setSocketTimeout(SOCKET_TIMEOUT_MS)
            .build();

        try (CloseableHttpClient client = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .build()) {

            HttpPost post = new HttpPost(endpointUrl);
            post.setHeader("Authorization", "Bearer " + token);
            post.setHeader("Content-Type", "application/json");
            post.setEntity(new StringEntity(requestBody.toString(), StandardCharsets.UTF_8));

            try (CloseableHttpResponse response = client.execute(post)) {
                int statusCode = response.getStatusLine().getStatusCode();
                String responseBody = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                long ms = System.currentTimeMillis() - t0;

                log.info("[Databricks] response http={} ms={} responseChars={}",
                    statusCode, ms, responseBody.length());
                log.debug("[Databricks] response body:\n{}", responseBody);

                if (statusCode < 200 || statusCode >= 300) {
                    log.error("[Databricks] API error http={} ms={} body={}", statusCode, ms, truncate(responseBody, 500));
                    throw new IOException("Databricks API returned HTTP " + statusCode + ": " + responseBody);
                }

                String content = extractAssistantMessage(responseBody);
                log.info("[Databricks] parsed assistant message chars={}", content.length());
                return content;
            }
        }
    }

    private String extractAssistantMessage(String responseBody) throws IOException {
        try {
            JSONObject json = new JSONObject(responseBody);
            JSONArray choices = json.getJSONArray("choices");
            if (choices.length() == 0) {
                throw new IOException("No choices in Databricks response");
            }
            String content = choices.getJSONObject(0).getJSONObject("message").getString("content");
            content = content.trim();
            if (content.startsWith("```")) {
                content = content.replaceAll("^```[a-zA-Z]*\\s*", "").replaceAll("```\\s*$", "").trim();
            }
            return content;
        } catch (Exception e) {
            log.error("[Databricks] parse failed: {}", truncate(responseBody, 500), e);
            throw new IOException("Failed to parse Databricks response: " + e.getMessage(), e);
        }
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
