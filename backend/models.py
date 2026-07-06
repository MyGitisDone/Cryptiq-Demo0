from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SetupRequest(BaseModel):
    tier: str = Field(default="instant")
    secret_message: str = Field(default="LOGIN", max_length=24)
    mlkem_param: str = Field(default="ML-KEM-768")


class AttackRequest(BaseModel):
    N: int
    e: int
    wrapped_key: int
    ciphertext: list[int]
    shots: int = Field(default=512, ge=64, le=4096)
    backend: str = Field(default="aer")
    ibm_backend_name: Optional[str] = None
