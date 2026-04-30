from typing import Any, Literal, Optional

from pydantic import BaseModel


Mode = Literal["fernet", "rsa", "hybrid"]


class EncryptRequest(BaseModel):
    mode: Mode
    plaintext: str
    fernet_key: Optional[str] = None
    public_key: Optional[str] = None
    return_telemetry: bool = False


class DecryptRequest(BaseModel):
    mode: Mode
    ciphertext: str
    fernet_key: Optional[str] = None
    private_key: Optional[str] = None
    encrypted_session_key: Optional[str] = None
    return_telemetry: bool = False


class SuccessResponse(BaseModel):
    success: bool = True
    mode: str
    ciphertext: Optional[str] = None
    plaintext: Optional[str] = None
    encrypted_session_key: Optional[str] = None
    telemetry: Optional[dict[str, Any]] = None
    message: str


class ErrorResponse(BaseModel):
    success: bool = False
    error: str
    error_code: str
    telemetry: Optional[dict[str, Any]] = None
