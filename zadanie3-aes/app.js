import { apiGet, apiPost, showStatus } from "../shared/api.js";

const $ = (id) => document.getElementById(id);

const els = {
  plaintext: $("plaintext"),
  ciphertext: $("ciphertext"),
  passphrase: $("passphrase"),
  keyBits: $("keyBits"),
  ivHex: $("ivHex"),
  decryptOut: $("decryptOut"),
  meta: $("meta"),
  status: $("status"),
};

async function withLoading(fn) {
  document.body.classList.add("loading");
  try {
    await fn();
  } finally {
    document.body.classList.remove("loading");
  }
}

$("btnRandomIv").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const data = await apiGet("/api/aes/random-iv");
      els.ivHex.value = data.ivHex;
      showStatus(els.status, "IV сгенерирован на сервере.");
    } catch (e) {
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnEncrypt").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const result = await apiPost("/api/aes/encrypt", {
        plaintext: els.plaintext.value,
        passphrase: els.passphrase.value,
        key_bits: Number(els.keyBits.value),
        iv_hex: els.ivHex.value.trim(),
      });
      els.ciphertext.value = result.ciphertext;
      if (result.ivHex) els.ivHex.value = result.ivHex;
      els.meta.textContent = [
        `Режим: AES-${result.keyBits}-${result.mode}`,
        result.ivHex ? `IV: ${result.ivHex}` : "",
        "Формат: Base64( IV || ciphertext )",
        "Ключ: SHA-256(фраза), усечение · Python cryptography",
      ].join("\n");
      showStatus(els.status, "Шифрование выполнено (Python).");
    } catch (e) {
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnDecrypt").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const result = await apiPost("/api/aes/decrypt", {
        ciphertext: els.ciphertext.value,
        passphrase: els.passphrase.value,
        key_bits: Number(els.keyBits.value),
      });
      els.decryptOut.value = result.plaintext;
      els.meta.textContent = [
        `Режим: AES-${result.keyBits}-${result.mode}`,
        result.ivHex ? `IV из пакета: ${result.ivHex}` : "",
        "Расшифровка успешна.",
      ].join("\n");
      showStatus(els.status, "Дешифрование выполнено (Python).");
    } catch (e) {
      els.decryptOut.value = "";
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnWrongKey").addEventListener("click", () =>
  withLoading(async () => {
    if (!els.ciphertext.value.trim()) {
      showStatus(els.status, "Сначала зашифруйте текст.", true);
      return;
    }
    try {
      await apiPost("/api/aes/decrypt", {
        ciphertext: els.ciphertext.value,
        passphrase: els.passphrase.value + "_wrong",
        key_bits: Number(els.keyBits.value),
      });
      showStatus(els.status, "Неожиданно: расшифровка с неверным ключом прошла.", true);
    } catch {
      els.decryptOut.value = "";
      showStatus(els.status, "Проверка: неверный ключ — ошибка (ожидаемо).", false);
    }
  })
);

$("btnSample").addEventListener("click", () => {
  els.plaintext.value = "Средство криптографической защиты информации";
  els.passphrase.value = "theor-info-2026";
  els.keyBits.value = "256";
  els.ivHex.value = "";
});
