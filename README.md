# Access Request AI Assistant

SailPoint IIQ plugin for approver-assist on access request work items. Builds flag-rich context from live IIQ objects; the LLM applies prompt rules when Databricks is configured (same pattern as Certification Launcher). Java rule engine is the offline/template fallback.

## Structure

```text
iiq-access-request-assistant/
├── build.xml
├── build.properties
├── config/
│   └── log4j2-accessRequestAssistant-snippet.properties
├── src/com/iam/plugin/accessrequestassistant/
│   ├── rest/AccessRequestResource.java
│   ├── service/          # context, rules, explain, Databricks
│   └── util/
└── web/
    ├── manifest.xml
    └── js/
        ├── accessRequestAiBrief.js
        └── workItemInject.js
```

## Build

Set `iiq.home` in `build.properties` (or `user.build.properties`) to your IIQ webapp path, then:

```bash
ant package
```

Output: `build/dist/accessRequestAssistant.<version>.<build>.zip`

Install via **Gear → Plugins → Install**.

## REST API

| Method | Path |
|--------|------|
| GET | `/plugin/rest/accessrequestassistant/workitems/{workItemId}/context` |
| GET | `/plugin/rest/accessrequestassistant/workitems/{workItemId}/ai-brief` |

`ai-brief` query params: `historyLookbackDays`, `maxPeersScan`, `narrativeMode`, `explain=false`

## Plugin settings

| Setting | Default |
|---------|---------|
| `historyLookbackDays` | 90 |
| `maxPeersScan` | 40 |
| `narrativeMode` | `auto` |
| `databricksHost` | workspace URL |
| `databricksEndpoint` | `access-request-ai-assist` |
| `databricksToken` | PAT |

## Logging (optional)

Append `config/log4j2-accessRequestAssistant-snippet.properties` to `WEB-INF/classes/log4j2.properties`.

## Architecture

| Step | Access Request Assistant | Certification Launcher |
|------|--------------------------|--------------------------|
| Context | Java builds flag JSON (`buildLlmContext`) | Java builds flag JSON per cert line |
| Rules | **LLM prompt rules** (Approve / Review Closely) | **LLM prompt rules** (Approve / Review / Revoke) |
| Fallback | Java `AccessRequestRuleEngine` when `narrativeMode=template` or Databricks unavailable | Context-only when not configured |
| Outcomes | `approve` \| `needs_manual_review` (no deny/revoke) | Approve \| Review Closely \| Revoke |

## Rules

**LLM path (default `narrativeMode=auto`):** prompt rules C1–C17 (review) and A1–A3 (approve) over inline flags (`identityInactive`, `linkDisabled`, `privateGroup`, `sox`, etc.).

**Java fallback (v1.3):** deterministic `approve` or `needs_manual_review` when Databricks is off or `narrativeMode=template`.
