"""
Central configuration.

Everything that could differ between your laptop and production lives here and
is read from environment variables (never hardcoded). Pydantic validates the
values at start-up, so a typo fails loudly on boot instead of silently at 3am.
"""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root = two levels up from this file (src/sentinelrag/config.py)
ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Gemini -------------------------------------------------------------
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash"
    gemini_judge_model: str = "gemini-3.1-flash-lite"

    # --- Embeddings ---------------------------------------------------------
    embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_model_dir: str = "models/all-MiniLM-L6-v2"
    enforce_model_signature: bool = True

    # --- Vector store -------------------------------------------------------
    chroma_dir: str = "data/chroma"
    collection_name: str = "kb"

    # --- Guardrails ---------------------------------------------------------
    injection_block_threshold: float = 0.75
    injection_flag_threshold: float = 0.45
    enable_llm_judge: bool = True
    require_human_approval: bool = True
    allowed_link_domains: str = "example.com"

    # --- Ops ----------------------------------------------------------------
    audit_log_path: str = "data/audit.log"
    max_tool_calls_per_request: int = 4

    # --- Derived helpers ----------------------------------------------------
    @property
    def model_dir_path(self) -> Path:
        return ROOT / self.embedding_model_dir

    @property
    def chroma_path(self) -> Path:
        return ROOT / self.chroma_dir

    @property
    def audit_path(self) -> Path:
        return ROOT / self.audit_log_path

    @property
    def link_domain_allowlist(self) -> list[str]:
        return [d.strip().lower() for d in self.allowed_link_domains.split(",") if d.strip()]


settings = Settings()
