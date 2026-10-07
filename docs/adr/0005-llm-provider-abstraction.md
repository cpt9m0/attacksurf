# 0005. Own LLM provider abstraction (Anthropic + OpenAI-compatible)

- Status: accepted
- Date: 2026-10-07

## Context
We support Anthropic and any OpenAI-compatible endpoint (OpenAI, OpenRouter, vLLM, ...). Orgs may
bring their own keys. No local models for now.

## Decision
A small `LLMProvider` protocol with two implementations using the official `anthropic` and
`openai` SDKs. No meta-libraries (e.g. LiteLLM). Structured outputs via pydantic schemas.
LLMs judge and explain scanner findings; they never detect or act on their own.

## Consequences
- Thin, auditable layer; smaller supply-chain surface.
- Adding a provider means writing an adapter.
- Structured-output behavior differs per provider; adapters handle fallback and validation.
