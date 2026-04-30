import base64
import os
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives import serialization
import httpx
from pydantic import ValidationError

from models.schemas import AssistantRequest, DecryptRequest, EncryptRequest, ValidateRequest
from services import fernet_service, hybrid_service, rsa_service


APP_VERSION = "3.0.0"


app = FastAPI(title="Encryptify", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


ERROR_MESSAGES = {
    "INVALID_KEY": "The key provided is invalid or does not match the ciphertext.",
    "CORRUPTED_CIPHERTEXT": "The ciphertext appears to be corrupted or has been modified.",
    "MISSING_FIELD": "Required field '{field}' is missing.",
    "UNSUPPORTED_MODE": "Unknown encryption mode. Choose fernet, rsa, or hybrid.",
    "PLAINTEXT_TOO_LONG": "RSA can only encrypt short messages (~190 bytes). Use Hybrid mode instead.",
    "INTERNAL_ERROR": "An unexpected error occurred.",
}


def error_response(
    error_code: str,
    status_code: int = 400,
    telemetry: dict[str, Any] | None = None,
    **kwargs: Any,
) -> JSONResponse:
    message = ERROR_MESSAGES.get(error_code, "Something went wrong.")
    content = {
        "success": False,
        "error": message.format(**kwargs),
        "error_code": error_code,
    }
    if telemetry is not None:
        content["telemetry"] = telemetry
    return JSONResponse(status_code=status_code, content=content)


def require_field(value: str | None, field: str) -> str | JSONResponse:
    if value is None or value.strip() == "":
        return error_response("MISSING_FIELD", field=field)
    return value


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    for error in exc.errors():
        location = error.get("loc", ())
        if location and location[-1] == "mode":
            return error_response("UNSUPPORTED_MODE", status_code=422)
        if error.get("type") == "missing":
            field = str(location[-1]) if location else "field"
            return error_response("MISSING_FIELD", status_code=422, field=field)
    return error_response("MISSING_FIELD", status_code=422, field="field")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return error_response("INTERNAL_ERROR", status_code=500)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": APP_VERSION}


@app.post("/api/validate")
async def validate(body: ValidateRequest):
    value = body.value.strip()
    if value == "":
        return {
            "valid": False,
            "field": body.field,
            "hint": "This field is empty.",
        }

    try:
        if body.field == "fernet_key":
            Fernet(value.encode())
            hint = "Valid Fernet key."
        elif body.field == "fernet_token":
            raw = base64.urlsafe_b64decode(value.encode())
            if not value.startswith("gAAAA") or len(raw) < 73:
                raise ValueError("Unexpected token prefix.")
            hint = "Token shape looks valid."
        elif body.field == "public_key":
            serialization.load_pem_public_key(value.encode())
            hint = "Valid PEM public key."
        elif body.field == "private_key":
            serialization.load_pem_private_key(value.encode(), password=None)
            hint = "Valid PEM private key."
        elif body.field == "encrypted_session_key":
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) < 128:
                raise ValueError("Too short for RSA ciphertext.")
            hint = "Base64 RSA ciphertext shape looks valid."
        else:
            return {"valid": False, "field": body.field, "hint": "Unsupported field."}
    except Exception:
        hints = {
            "fernet_key": "A Fernet key should be 44 characters of Base64url.",
            "fernet_token": "A Fernet token usually starts with gAAAA and must be copied completely.",
            "public_key": "PEM public keys start with '-----BEGIN PUBLIC KEY-----'.",
            "private_key": "PEM private keys start with '-----BEGIN PRIVATE KEY-----'.",
            "encrypted_session_key": "Encrypted session keys are Base64 RSA ciphertext values.",
        }
        return {"valid": False, "field": body.field, "hint": hints[body.field]}

    return {"valid": True, "field": body.field, "hint": hint}


@app.post("/api/assistant")
async def assistant(body: AssistantRequest):
    question = body.question.strip()
    if not question:
        return {"success": False, "error": "Please enter a question.", "error_code": "MISSING_FIELD"}

    if not _is_crypto_question(question):
        return {
            "success": True,
            "answer": "I can help with cryptography and the Encryptify tool. Try asking about keys, IVs, HMAC, RSA, Fernet, Hybrid mode, or why a decryption failed.",
            "source": "local",
        }

    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        try:
            return {
                "success": True,
                "answer": await _ask_anthropic(api_key, question, body.mode, body.last_operation),
                "source": "anthropic",
            }
        except Exception:
            pass

    return {
        "success": True,
        "answer": _local_assistant_answer(question, body.mode),
        "source": "local",
    }


@app.post("/api/fernet/key")
async def generate_fernet_key():
    return {"success": True, "fernet_key": fernet_service.generate_key()}


@app.post("/api/rsa/keypair")
async def generate_rsa_keypair():
    public_key, private_key = rsa_service.generate_keypair()
    return {
        "success": True,
        "public_key": public_key,
        "private_key": private_key,
    }


@app.post("/api/encrypt")
async def encrypt(body: EncryptRequest):
    plaintext = require_field(body.plaintext, "plaintext")
    if isinstance(plaintext, JSONResponse):
        return plaintext

    try:
        if body.mode == "fernet":
            fernet_key = require_field(body.fernet_key, "fernet_key")
            if isinstance(fernet_key, JSONResponse):
                return fernet_key
            if body.return_telemetry:
                encrypted = fernet_service.encrypt_with_telemetry(plaintext, fernet_key)
                ciphertext = encrypted["ciphertext"]
                telemetry = encrypted["telemetry"]
            else:
                ciphertext = fernet_service.encrypt(plaintext, fernet_key)
                telemetry = None
            encrypted_session_key = None
        elif body.mode == "rsa":
            public_key = require_field(body.public_key, "public_key")
            if isinstance(public_key, JSONResponse):
                return public_key
            if body.return_telemetry:
                encrypted = rsa_service.encrypt_with_telemetry(plaintext, public_key)
                ciphertext = encrypted["ciphertext"]
                telemetry = encrypted["telemetry"]
            else:
                ciphertext = rsa_service.encrypt(plaintext, public_key)
                telemetry = None
            encrypted_session_key = None
        elif body.mode == "hybrid":
            public_key = require_field(body.public_key, "public_key")
            if isinstance(public_key, JSONResponse):
                return public_key
            encrypted = (
                hybrid_service.encrypt_with_telemetry(plaintext, public_key)
                if body.return_telemetry
                else hybrid_service.encrypt(plaintext, public_key)
            )
            ciphertext = encrypted["ciphertext"]
            encrypted_session_key = encrypted["encrypted_session_key"]
            telemetry = encrypted.get("telemetry") if body.return_telemetry else None
        else:
            return error_response("UNSUPPORTED_MODE")
    except ValueError as exc:
        if str(exc) == "PLAINTEXT_TOO_LONG":
            return error_response("PLAINTEXT_TOO_LONG")
        return error_response("INVALID_KEY")
    except (InvalidKey, ValidationError):
        return error_response("INVALID_KEY")
    except Exception:
        return error_response("INVALID_KEY")

    response = {
        "success": True,
        "mode": body.mode,
        "ciphertext": ciphertext,
        "encrypted_session_key": encrypted_session_key,
        "message": "Encryption successful",
    }
    if telemetry is not None:
        response["telemetry"] = telemetry
    return response


@app.post("/api/decrypt")
async def decrypt(body: DecryptRequest):
    ciphertext = require_field(body.ciphertext, "ciphertext")
    if isinstance(ciphertext, JSONResponse):
        return ciphertext

    try:
        if body.mode == "fernet":
            fernet_key = require_field(body.fernet_key, "fernet_key")
            if isinstance(fernet_key, JSONResponse):
                return fernet_key
            if body.return_telemetry:
                decrypted = fernet_service.decrypt_with_telemetry(ciphertext, fernet_key)
                plaintext = decrypted["plaintext"]
                telemetry = decrypted["telemetry"]
            else:
                plaintext = fernet_service.decrypt(ciphertext, fernet_key)
                telemetry = None
        elif body.mode == "rsa":
            private_key = require_field(body.private_key, "private_key")
            if isinstance(private_key, JSONResponse):
                return private_key
            if body.return_telemetry:
                decrypted = rsa_service.decrypt_with_telemetry(ciphertext, private_key)
                plaintext = decrypted["plaintext"]
                telemetry = decrypted["telemetry"]
            else:
                plaintext = rsa_service.decrypt(ciphertext, private_key)
                telemetry = None
        elif body.mode == "hybrid":
            private_key = require_field(body.private_key, "private_key")
            encrypted_session_key = require_field(
                body.encrypted_session_key,
                "encrypted_session_key",
            )
            if isinstance(private_key, JSONResponse):
                return private_key
            if isinstance(encrypted_session_key, JSONResponse):
                return encrypted_session_key
            if body.return_telemetry:
                decrypted = hybrid_service.decrypt_with_telemetry(
                    ciphertext,
                    encrypted_session_key,
                    private_key,
                )
                plaintext = decrypted["plaintext"]
                telemetry = decrypted["telemetry"]
            else:
                plaintext = hybrid_service.decrypt(ciphertext, encrypted_session_key, private_key)
                telemetry = None
        else:
            return error_response("UNSUPPORTED_MODE")
    except fernet_service.FernetTelemetryError as exc:
        return error_response(exc.error_code, telemetry=exc.telemetry)
    except InvalidToken:
        return error_response("INVALID_KEY")
    except ValueError as exc:
        if str(exc) == "CORRUPTED_CIPHERTEXT":
            return error_response("CORRUPTED_CIPHERTEXT")
        return error_response("INVALID_KEY")
    except (InvalidKey, ValidationError):
        return error_response("INVALID_KEY")
    except Exception:
        return error_response("INVALID_KEY")

    response = {
        "success": True,
        "mode": body.mode,
        "plaintext": plaintext,
        "message": "Decryption successful",
    }
    if telemetry is not None:
        response["telemetry"] = telemetry
    return response


def _is_crypto_question(question: str) -> bool:
    terms = {
        "aes",
        "cbc",
        "cipher",
        "ciphertext",
        "decrypt",
        "encrypt",
        "fernet",
        "hash",
        "hmac",
        "hybrid",
        "iv",
        "key",
        "nonce",
        "oaep",
        "padding",
        "pkcs7",
        "plaintext",
        "private",
        "public",
        "rsa",
        "session",
        "signature",
        "token",
    }
    lowered = question.lower()
    return any(term in lowered for term in terms)


async def _ask_anthropic(
    api_key: str,
    question: str,
    mode: str,
    last_operation: str | None,
) -> str:
    system_prompt = (
        "You are a cryptography teaching assistant embedded in Encryptify, "
        "an academic web application for IT360 at Tunis Business School. "
        f"The student is currently using {mode} mode and just "
        f"{last_operation or 'opened the app'}. "
        "Answer questions about cryptography clearly and concisely, in no more "
        "than four sentences. Use concrete examples when possible. Never discuss "
        "topics unrelated to cryptography or the Encryptify tool."
    )
    async with httpx.AsyncClient(timeout=15) as client:
        response = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "content-type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514"),
                "max_tokens": 220,
                "system": system_prompt,
                "messages": [{"role": "user", "content": question}],
            },
        )
        response.raise_for_status()
    data = response.json()
    return data.get("content", [{}])[0].get("text", "Unable to answer right now.")


def _local_assistant_answer(question: str, mode: str) -> str:
    q = question.lower()
    if "iv" in q or "nonce" in q:
        return (
            "An IV makes the first encrypted block different even when the same "
            "plaintext is encrypted twice. In Fernet's CBC mode, the IV is XORed "
            "with the first plaintext block before AES runs. Encryptify shows the "
            "real IV bytes in the Process Theater."
        )
    if "hmac" in q or "signature" in q or "tamper" in q:
        return (
            "HMAC is the integrity check: it proves the token bytes were not "
            "changed and that the correct Fernet key was used. During decryption, "
            "Encryptify verifies HMAC before releasing plaintext. If one byte is "
            "modified, the comparison fails."
        )
    if "oaep" in q or "padding" in q:
        return (
            "Padding gives cryptographic algorithms the structure they require. "
            "PKCS7 fills Fernet's final AES block, while OAEP adds randomness and "
            "structure before RSA encryption. That randomness is why repeated "
            "RSA encryptions of the same message differ."
        )
    if "rsa" in q or "key size" in q or "limit" in q:
        return (
            "RSA uses a public key to encrypt and a private key to decrypt. With "
            "RSA-2048 and OAEP-SHA256, the direct plaintext limit is about 190 "
            "bytes, so it is best for short data or wrapping keys. For long text, "
            "Hybrid mode is the practical design."
        )
    if "hybrid" in q or "session" in q:
        return (
            "Hybrid mode generates a fresh Fernet session key for the message, "
            "encrypts the text with Fernet, then encrypts that session key with "
            "RSA. This gives Fernet's speed and RSA's safe key transport. The "
            "recipient needs both outputs to decrypt."
        )
    return (
        f"In {mode} mode, focus on what data is protected and which key can reverse "
        "the operation. Fernet uses one shared key, RSA separates public and private "
        "keys, and Hybrid uses RSA to carry a one-time Fernet session key."
    )
