"""Which provider config an org's AI calls use (ADR 0019)."""

from attacksurf.config import Settings
from attacksurf.domain.llm import KeySource, LLMConfig, OrgLLMConfig


def resolve_llm_config(org: OrgLLMConfig | None, settings: Settings) -> LLMConfig | None:
    """The org's own config if it has a key, else the instance config, else None (AI off).

    Each source brings its provider, model and base URL along with its key: an org's model is
    never sent with the instance key, and a failing org key never falls back to the instance.
    The instance config needs both a key and a model, since model names have no default.
    """
    if org is not None and org.api_key is not None:
        return LLMConfig(
            provider=org.provider,
            model=org.model,
            api_key=org.api_key,
            source=KeySource.ORG,
            base_url=org.base_url,
        )
    if settings.llm_api_key is None or settings.llm_model is None:
        return None
    return LLMConfig(
        provider=settings.llm_provider,
        model=settings.llm_model,
        api_key=settings.llm_api_key,
        source=KeySource.INSTANCE,
        base_url=settings.llm_base_url,
    )
