from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.fernet import InvalidToken
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from models.schemas import DecryptRequest, EncryptRequest
from services import fernet_service, hybrid_service, rsa_service


app = FastAPI(title="Encryptify", version="2.0.0")
templates = Jinja2Templates(directory="templates")


ERROR_MESSAGES = {
    "INVALID_KEY": "The key provided is invalid or does not match the ciphertext.",
    "CORRUPTED_CIPHERTEXT": "The ciphertext appears to be corrupted or has been modified.",
    "MISSING_FIELD": "Required field '{field}' is missing.",
    "UNSUPPORTED_MODE": "Unknown encryption mode. Choose fernet, rsa, or hybrid.",
    "PLAINTEXT_TOO_LONG": "RSA can only encrypt short messages (~190 bytes). Use Hybrid mode instead.",
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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


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
