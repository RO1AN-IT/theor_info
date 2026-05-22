# Theor Info — задания 2 и 3

Лаборатория для курса «Теория информации»: **LZ78** (сжатие) и **AES** (шифрование).  
Вся логика на **Python** (FastAPI + cryptography).

## Запуск

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Откройте: **http://localhost:8000/**

На главной странице должна появиться строка `Сервер: ok · backend: python`.

## Структура

```
backend/
  main.py           # FastAPI + раздача статики
  lz78_codec.py     # LZ78
  aes_protocol.py   # AES-CBC
zadanie2-lz78/      # UI задание 2
zadanie3-aes/       # UI задание 3
shared/             # style.css, api.js
tests/test_python.py
```

## API

| Метод | Путь | Описание |
|-------|------|----------|
| GET | `/api/health` | Проверка сервера |
| POST | `/api/lz78/encode` | `{ text, max_dict_size }` |
| POST | `/api/lz78/decode` | `{ tokens, max_dict_size }` |
| POST | `/api/aes/encrypt` | `{ plaintext, passphrase, key_bits, iv_hex? }` |
| POST | `/api/aes/decrypt` | `{ ciphertext, passphrase, key_bits }` |
| GET | `/api/aes/random-iv` | Случайный IV |

## Тесты

```bash
python3 tests/test_python.py
```

## Задание 2 — LZ78

- Словарь: индекс `0` = `""`
- Токены: JSON `[{"index":0,"char":"a"}, ...]`
- При заполнении словаря новые фразы не добавляются

## Задание 3 — AES

- AES-128/192/256, режим **CBC**, PKCS#7
- Ключ: SHA-256(парольная фраза), усечение
- Вывод: `Base64(IV ‖ ciphertext)`
