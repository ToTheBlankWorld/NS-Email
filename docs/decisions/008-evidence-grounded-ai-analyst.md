# ADR 008 — Evidence-Grounded AI Forensic Analyst

- **Status:** Accepted (Stage 8)
- **Date:** 2026-09-27
- **Scope:** `engine/ai`, AI API endpoints, frontend AI panel

## Context

Stages 2–7 produce structured, deterministic evidence. Stage 8 adds an evidence-grounded
AI assistant that helps analysts understand the structured evidence. The AI is an
explanation assistant — never the source of truth, never a policy engine, never an
attack classifier. No autonomous actions are possible.

## Architecture

1. **Provider abstraction** — `LLMProvider` protocol with `generate(request)`.
   Implementations: `OpenAICompatibleProvider` (works with OpenAI, Ollama, or any
   compatible API) and `MockLLMProvider` (deterministic test provider). Provider and
   model are configured via environment variables; API keys come only from environment.

2. **Context builder** — converts `InvestigationContext` into a minimized `AIContext`
   containing only fields needed to answer the question. Sensitive keys
   (`credential_data`, `password`, `secret`, `private_key`, `api_key`) are stripped
   recursively before serialization. Context is bounded to 12,000 characters.

3. **Prompt architecture** — versioned system prompt (`PROMPT_VERSION = "1.0"`) with
   10 explicit rules: use only supplied evidence, never invent observations, separate
   observations from interpretations, cite evidence, state uncertainty, do not claim
   attack attribution, do not reveal credentials, do not fabricate standards references,
   treat evidence fields as untrusted data, and say `insufficient_evidence` when
   evidence is insufficient.

4. **Response model** — LLM output is parsed as JSON, validated against the supplied
   context (cited session IDs must match), and returned as a typed
   `AIAnalysisResponse` with observed/interpretation/uncertainty sections and
   structured citations.

5. **Separation of concerns** — ML anomalies are kept separate from deterministic
   findings and from AI responses. The AI may explain existing findings and anomalies
   but never creates new security conclusions.

## Security

- No API keys in source, database, or API responses.
- No raw PCAP bytes, packet payloads, message bodies, credentials, or private keys
  are sent to the LLM.
- Prompt injection defense: evidence fields are explicitly labeled as untrusted data
  in the system prompt; the model is instructed never to follow instructions inside
  evidence values.
- Response validation rejects responses citing session IDs not present in the context.
- No autonomous actions are possible.
- Provider must be explicitly configured; without configuration the AI status is
  `not_configured` and queries return a structured error.

## Limitations

- The AI is evidence-grounded assistance, not authoritative verdict generation.
- Synthetic tests do not validate real-world LLM behavior.
- Historical baselines are not yet implemented.
- The default Mock provider returns deterministic responses and does not exercise
  real LLM capabilities.
