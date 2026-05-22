"""FastAPI: API + статика для theor_info."""

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aes_protocol import aes_decrypt, aes_encrypt, random_iv_hex
from lz78_codec import lz78_decode, lz78_encode

ROOT = Path(__file__).resolve().parent.parent

app = FastAPI(title="Theor Info", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class Lz78EncodeRequest(BaseModel):
    text: str = ""
    max_dict_size: int = Field(4096, ge=2, le=65536)


class Lz78DecodeRequest(BaseModel):
    tokens: str | list[dict] = ""
    max_dict_size: int = Field(4096, ge=2, le=65536)


class AesEncryptRequest(BaseModel):
    plaintext: str = ""
    passphrase: str
    key_bits: int = Field(256, ge=128, le=256)
    iv_hex: str = ""


class AesDecryptRequest(BaseModel):
    ciphertext: str = ""
    passphrase: str
    key_bits: int = Field(256, ge=128, le=256)


@app.get("/api/health")
def health():
    return {"status": "ok", "backend": "python"}


@app.post("/api/lz78/encode")
def api_lz78_encode(body: Lz78EncodeRequest):
    try:
        return lz78_encode(body.text, body.max_dict_size)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/lz78/decode")
def api_lz78_decode(body: Lz78DecodeRequest):
    try:
        text = lz78_decode(body.tokens, body.max_dict_size)
        return {"text": text}
    except (ValueError, json.JSONDecodeError) as exc:  # noqa: PERF203
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/aes/random-iv")
def api_random_iv():
    return {"ivHex": random_iv_hex()}


@app.post("/api/aes/encrypt")
def api_aes_encrypt(body: AesEncryptRequest):
    try:
        if body.key_bits not in (128, 192, 256):
            raise ValueError("Длина ключа AES: 128, 192 или 256 бит")
        return aes_encrypt(body.plaintext, body.passphrase, body.key_bits, body.iv_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/aes/decrypt")
def api_aes_decrypt(body: AesDecryptRequest):
    try:
        if body.key_bits not in (128, 192, 256):
            raise ValueError("Длина ключа AES: 128, 192 или 256 бит")
        return aes_decrypt(body.ciphertext, body.passphrase, body.key_bits)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Ошибка расшифровки (неверный ключ или данные)") from exc


app.mount("/", StaticFiles(directory=str(ROOT), html=True), name="static")
