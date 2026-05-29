

from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

# Допустимые длины ключа в битах
VALID_KEY_BITS = (128, 192, 256)

# Таблица замен байта (S-box) из стандарта AES
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Обратная S-box для расшифровки
INV_SBOX = [SBOX.index(i) for i in range(256)]

# Константы для расширения ключа
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _validate_key_bits(key_bits: int) -> None:
    """Проверяет, что длина ключа — 128, 192 или 256 бит"""
    if key_bits not in VALID_KEY_BITS:
        raise ValueError("Длина ключа AES: 128, 192 или 256 бит")


def derive_aes_key(passphrase: str, key_bits: int) -> bytes:
    """
    Строит байты ключа из парольной фразы
    Берём SHA-256 от фразы и обрезаем до нужной длины 
    """
    _validate_key_bits(key_bits)
    if not passphrase:
        raise ValueError("Введите ключ (парольную фразу)")
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return digest[: key_bits // 8]


def bytes_to_hex(data: bytes) -> str:
    """Переводит байты в строку hex (для отображения IV)"""
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Читает hex-строку и возвращает байты (для IV из формы)"""
    clean = hex_str.replace(" ", "")
    if len(clean) % 2 != 0:
        raise ValueError("IV: только hex-пары")
    try:
        return bytes.fromhex(clean)
    except ValueError as exc:
        raise ValueError("IV: только hex-пары") from exc


def random_iv_hex() -> str:
    """Случайный IV длиной 16 байт в виде hex"""
    return bytes_to_hex(os.urandom(16))


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Дополнение PKCS#7: к данным добавляется n байт со значением n,
    чтобы длина стала кратной размеру блока (16 для AES)
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Убирает PKCS#7-дополнение с конца расшифрованных данных"""
    if not data or len(data) % block_size != 0:
        raise ValueError("Некорректное дополнение PKCS#7")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Некорректное дополнение PKCS#7")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Некорректное дополнение PKCS#7")
    return data[:-pad_len]


def _xtime(value: int) -> int:
    """Умножение байта на x в поле GF(2^8) — нужно для MixColumns"""
    value &= 0xFF
    if value & 0x80:
        return ((value << 1) ^ 0x1B) & 0xFF
    return (value << 1) & 0xFF


def _sub_bytes(state: list[int]) -> None:
    """Заменяет каждый байт состояния по таблице S-box"""
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    """Обратная замена байтов"""
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    """Циклически сдвигает строки матрицы состояния 4×4"""
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state: list[int]) -> None:
    """Обратный сдвиг строк"""
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _gf_mul(a: int, b: int) -> int:
    """Умножение двух байт в поле GF(2^8) — для MixColumns"""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result & 0xFF


def _mix_columns(state: list[int]) -> None:
    """Перемешивает столбцы состояния (линейное преобразование в GF(2^8))"""
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _inv_mix_columns(state: list[int]) -> None:
    """Обратное преобразование MixColumns"""
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        state[i + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        state[i + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        state[i + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)


def _add_round_key(state: list[int], round_key: bytes) -> None:
    """Побайтово складывает (XOR) состояние с раундовым ключом"""
    for i in range(16):
        state[i] ^= round_key[i]


def _key_expansion(key: bytes) -> list[bytes]:
    """
    Разворачивает ключ в набор раундовых ключей
    Для AES-128 — 11 ключей по 16 байт, для 192 — 13, для 256 — 15
    """
    nk = len(key) // 4  # число 32-битных слов в ключе: 4, 6 или 8
    nr = nk + 6  # число раундов

    # Слова ключа по 4 байта
    words: list[list[int]] = [list(key[i : i + 4]) for i in range(0, len(key), 4)]

    i = nk
    while len(words) < 4 * (nr + 1):
        temp = words[-1][:]
        if i % nk == 0:
            # RotWord + SubWord + XOR с константой раунда
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            # Дополнительный шаг только для AES-256
            temp = [SBOX[b] for b in temp]
        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])
        i += 1

    round_keys: list[bytes] = []
    for rnd in range(nr + 1):
        chunk: list[int] = []
        for c in range(4):
            chunk.extend(words[rnd * 4 + c])
        round_keys.append(bytes(chunk))
    return round_keys


def _encrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Шифрует один 16-байтный блок AES"""
    state = list(block)
    rounds = len(round_keys) - 1

    _add_round_key(state, round_keys[0])
    for rnd in range(1, rounds):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[rounds])
    return bytes(state)


def _decrypt_block(block: bytes, round_keys: list[bytes]) -> bytes:
    """Расшифровывает один 16-байтный блок AES"""
    state = list(block)
    rounds = len(round_keys) - 1

    _add_round_key(state, round_keys[rounds])
    for rnd in range(rounds - 1, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Шифрует данные в режиме CBC
    Каждый блок сначала XOR с предыдущим шифротекстом (или IV), потом AES
    """
    round_keys = _key_expansion(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        xored = bytes(b ^ prev[i] for i, b in enumerate(block))
        enc = _encrypt_block(xored, round_keys)
        out.extend(enc)
        prev = enc
    return bytes(out)


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровка CBC: расшифровали блок, затем XOR с предыдущим и IV"""
    round_keys = _key_expansion(key)
    out = bytearray()
    prev = iv
    for offset in range(0, len(data), 16):
        block = data[offset : offset + 16]
        dec = _decrypt_block(block, round_keys)
        plain = bytes(b ^ prev[i] for i, b in enumerate(dec))
        out.extend(plain)
        prev = block
    return bytes(out)


def aes_encrypt(
    plaintext: str,
    passphrase: str,
    key_bits: int = 256,
    iv_hex: str = "",
) -> dict[str, Any]:
    """
    Шифрует строку UTF-8
    """
    key = derive_aes_key(passphrase, key_bits)
    data = plaintext.encode("utf-8")

    if iv_hex:
        iv = hex_to_bytes(iv_hex)
        if len(iv) != 16:
            raise ValueError("IV должен быть 16 байт (32 hex-символа)")
    else:
        iv = os.urandom(16)

    padded = pkcs7_pad(data)
    encrypted = _aes_cbc_encrypt(padded, key, iv)
    packed = iv + encrypted

    return {
        "ciphertext": base64.b64encode(packed).decode("ascii"),
        "ivHex": bytes_to_hex(iv),
        "mode": "CBC",
        "keyBits": key_bits,
    }


def aes_decrypt(
    ciphertext_b64: str,
    passphrase: str,
    key_bits: int = 256,
) -> dict[str, Any]:
    """
    Расшифровывает Base64 обратно в UTF-8 строку
    """
    key = derive_aes_key(passphrase, key_bits)
    packed = base64.b64decode(ciphertext_b64.strip())

    if len(packed) < 17:
        raise ValueError("Слишком короткий шифротекст для CBC")

    iv = packed[:16]
    ciphertext = packed[16:]
    padded = _aes_cbc_decrypt(ciphertext, key, iv)
    data = pkcs7_unpad(padded)

    return {
        "plaintext": data.decode("utf-8"),
        "ivHex": bytes_to_hex(iv),
        "mode": "CBC",
        "keyBits": key_bits,
    }
