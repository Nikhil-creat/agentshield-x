# AI assistant

AgentShield-X ships a documentation assistant in three forms. All use **your own free API key** (bring your own key). Supported providers: **Groq** (`gsk_...`) and **Google Gemini** (`AIza...`).

| Form | Where | Guard strength |
|------|-------|----------------|
| Website page | `assistant.html` on the project site | Browser guard: secret check, length and rate limits, injected-instruction filter on retrieved docs, text-only output, output redaction |
| CLI | `agentshield chat` | Full pipeline: `check_input`, `check_rag` (quarantine and spotlight), output secret redaction |
| API | `POST /v1/assistant/chat` | Same as the CLI, behind the normal token, roles and rate limits. Enabled only when the server has `GROQ_API_KEY` or `GEMINI_API_KEY`. |

## Provider and model auto-detection

1. **Provider** is detected from the key prefix: `gsk_` is Groq, `AIza` is Gemini. Anything else is rejected before any request is made.
2. **Models** are fetched live from the provider (`GET /models`). Non-chat models are dropped: speech, text-to-speech, guard, embedding, image, live and experimental models, and models flagged inactive.
3. **Ranking** is a heuristic: larger and stable general models first for Groq; the newest stable Flash first for Gemini, because free-tier quotas are larger for Flash than for Pro. Preview and dated snapshots rank lower.
4. **Fallback**: if the chosen model is rate limited (429), retired (404/410) or unavailable, the next best of the top three is tried. An authentication error (401/403) stops immediately and is never retried on another model.

The Python (`agentshield/llm.py`) and browser (`web/assistant.js`) rankings are tested against the same fixture (`tests/fixtures/models.json`) and must agree. The ranking is not a benchmark. Provider model names and free-tier quotas change; the live list is what is used.

## Security model

- **The website has no server and cannot hold your key.** You paste it; it lives in tab memory, or in `sessionStorage` if you opt in. "Forget key" clears it. Do not paste a key you cannot rotate.
- **Network scope**: a content security policy on the assistant page allows requests only to this site, `api.groq.com` and `generativelanguage.googleapis.com`. Every other page allows none.
- **Hard-coded endpoints.** URLs are built from constants. The key is sent only in a header (`Authorization` or `x-goog-api-key`), never in a URL. Redirects are refused. Errors and logs have the key masked.
- **Grounding.** The model receives only retrieved documentation, wrapped in `<docs>` and labelled as data. It has no tools, no network and no file access.
- **Output**: shown as text, never HTML. Credential-shaped strings are redacted.
- **Never commit keys.** `.gitignore`, gitleaks and the release builder's secret scan exist to catch this. If you pasted a key into a chat, a screenshot or an issue, revoke it and create a new one.

## Limits

- 2000 characters per question; 3 seconds between questions; 30 questions per browser session; a 6-turn memory window; sessions on the server are capped (LRU).
- The browser guard is weaker than the Python engine; it uses simple patterns, not the full scanner. Paraphrased injections can pass it. The model may also answer wrongly; check the linked docs.
- Provider behaviour from a browser (CORS, quotas, model availability) depends on the provider and is outside this project's control. Use the CLI if the browser path is blocked.
- Free-tier data may be used by the provider under its own terms. Do not send confidential material.

## CLI

```bash
export GROQ_API_KEY=...        # or GEMINI_API_KEY
agentshield chat               # prints the provider and the auto-selected model
agentshield chat --provider gemini
```

`/reset` clears the session; `/quit` exits.
