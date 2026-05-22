"""LZ78: словарное кодирование и декодирование."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class Lz78Token:
    index: int
    char: str

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "char": self.char}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Lz78Token:
        if not isinstance(data.get("index"), int) or data["index"] < 0:
            raise ValueError("Недопустимый индекс токена")
        if not isinstance(data.get("char"), str):
            raise ValueError("Поле char должно быть строкой")
        return cls(index=data["index"], char=data["char"])


def _validate_dict_size(max_dict_size: int) -> None:
    if not isinstance(max_dict_size, int) or max_dict_size < 2:
        raise ValueError("Размер словаря должен быть целым числом ≥ 2")


def lz78_encode(text: str, max_dict_size: int) -> dict[str, Any]:
    _validate_dict_size(max_dict_size)

    index_by_string: dict[str, int] = {"": 0}
    dictionary: list[str] = [""]
    tokens: list[Lz78Token] = []

    def add_entry(phrase: str) -> None:
        if len(dictionary) >= max_dict_size or phrase in index_by_string:
            return
        idx = len(dictionary)
        dictionary.append(phrase)
        index_by_string[phrase] = idx

    pos = 0
    while pos < len(text):
        w = ""
        i = pos
        while i < len(text):
            candidate = text[pos : i + 1]
            if candidate in index_by_string:
                w = candidate
                i += 1
            else:
                break

        if i >= len(text):
            if w:
                tokens.append(Lz78Token(index_by_string[w], ""))
            break

        c = text[i]
        idx = index_by_string[w]
        tokens.append(Lz78Token(idx, c))
        add_entry(w + c)
        pos = i + 1

    serialized = serialize_tokens(tokens)
    original_bytes = len(text.encode("utf-8"))
    coded_bytes = len(serialized.encode("utf-8"))

    return {
        "tokens": [t.to_dict() for t in tokens],
        "dictionary": list(dictionary),
        "stats": {
            "inputChars": len(text),
            "tokenCount": len(tokens),
            "dictionarySize": len(dictionary),
            "maxDictSize": max_dict_size,
            "compressionRatio": coded_bytes / original_bytes if original_bytes else 1.0,
            "serialized": serialized,
            "human": format_tokens_human(tokens),
        },
    }


def lz78_decode(
    tokens: list[dict[str, Any]] | list[Lz78Token] | str,
    max_dict_size: int,
) -> str:
    _validate_dict_size(max_dict_size)
    if isinstance(tokens, str):
        parsed = parse_tokens(tokens)
    elif tokens and isinstance(tokens[0], Lz78Token):
        parsed = tokens  # type: ignore[assignment]
    else:
        parsed = [Lz78Token.from_dict(t) for t in tokens]  # type: ignore[arg-type]

    index_by_string: dict[str, int] = {"": 0}
    dictionary: list[str] = [""]
    output: list[str] = []

    def add_entry(phrase: str) -> None:
        if len(dictionary) >= max_dict_size or phrase in index_by_string:
            return
        idx = len(dictionary)
        dictionary.append(phrase)
        index_by_string[phrase] = idx

    for token in parsed:
        if token.index < 0 or token.index >= len(dictionary):
            raise ValueError(f"Недопустимый индекс словаря: {token.index}")
        w = dictionary[token.index]
        output.append(w)
        if token.char == "":
            continue
        output.append(token.char)
        add_entry(w + token.char)

    return "".join(output)


def serialize_tokens(tokens: list[Lz78Token]) -> str:
    return json.dumps([t.to_dict() for t in tokens], ensure_ascii=False)


def parse_tokens(raw: str | list[dict[str, Any]]) -> list[Lz78Token]:
    if isinstance(raw, list):
        return [Lz78Token.from_dict(t) for t in raw]

    trimmed = raw.strip()
    if not trimmed:
        return []

    if trimmed.startswith("["):
        data = json.loads(trimmed)
        if not isinstance(data, list):
            raise ValueError("Ожидается JSON-массив токенов")
        return [Lz78Token.from_dict(t) for t in data]

    result: list[Lz78Token] = []
    for i, part in enumerate(trimmed.split()):
        if ":" not in part:
            raise ValueError(f'Токен {i + 1}: ожидается "индекс:символ" или JSON')
        colon = part.index(":")
        index = int(part[:colon])
        char = part[colon + 1 :]
        if char == "∅":
            char = ""
        result.append(Lz78Token(index, char))
    return result


def format_tokens_human(tokens: list[Lz78Token]) -> str:
    parts: list[str] = []
    for t in tokens:
        ch = "∅" if t.char == "" else json.dumps(t.char, ensure_ascii=False)[1:-1]
        parts.append(f"{t.index}:{ch}")
    return " ".join(parts)
