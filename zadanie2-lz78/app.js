import { apiPost, formatDict, showStatus } from "../shared/api.js";

const $ = (id) => document.getElementById(id);

const els = {
  dictSize: $("dictSize"),
  inputText: $("inputText"),
  tokensOut: $("tokensOut"),
  dictOut: $("dictOut"),
  statsOut: $("statsOut"),
  decodeTokens: $("decodeTokens"),
  decodeSize: $("decodeSize"),
  decodeOut: $("decodeOut"),
  status: $("status"),
};

els.dictSize.addEventListener("input", () => {
  els.decodeSize.value = els.dictSize.value;
});

async function withLoading(fn) {
  document.body.classList.add("loading");
  try {
    await fn();
  } finally {
    document.body.classList.remove("loading");
  }
}

$("btnEncode").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const data = await apiPost("/api/lz78/encode", {
        text: els.inputText.value,
        max_dict_size: Number(els.dictSize.value),
      });

      els.tokensOut.value = data.stats.serialized;
      els.decodeTokens.value = data.stats.serialized;
      els.dictOut.textContent = formatDict(data.dictionary);
      els.statsOut.textContent = [
        `Символов в тексте: ${data.stats.inputChars}`,
        `Токенов: ${data.stats.tokenCount}`,
        `Записей в словаре: ${data.stats.dictionarySize} / лимит ${data.stats.maxDictSize}`,
        `Отношение (JSON / UTF-8): ${(data.stats.compressionRatio * 100).toFixed(1)}%`,
        `Читаемый вид: ${data.stats.human}`,
        data.stats.compressionRatio < 1
          ? "Сжатие по этой метрике есть."
          : "Сжатия нет (нормально для короткого или случайного текста).",
      ].join("\n");

      showStatus(els.status, "Кодирование выполнено (Python).");
    } catch (e) {
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnDecode").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const data = await apiPost("/api/lz78/decode", {
        tokens: els.decodeTokens.value,
        max_dict_size: Number(els.decodeSize.value),
      });
      els.decodeOut.value = data.text;
      showStatus(els.status, "Декодирование выполнено (Python).");
    } catch (e) {
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnRoundTrip").addEventListener("click", () =>
  withLoading(async () => {
    try {
      const enc = await apiPost("/api/lz78/encode", {
        text: els.inputText.value,
        max_dict_size: Number(els.dictSize.value),
      });
      const dec = await apiPost("/api/lz78/decode", {
        tokens: enc.stats.serialized,
        max_dict_size: Number(els.decodeSize.value),
      });
      els.tokensOut.value = enc.stats.serialized;
      els.decodeTokens.value = enc.stats.serialized;
      els.decodeOut.value = dec.text;
      els.dictOut.textContent = formatDict(enc.dictionary);
      const ok = els.inputText.value === dec.text;
      showStatus(
        els.status,
        ok ? "Round-trip OK: тексты совпали." : "Ошибка round-trip: тексты не совпали.",
        !ok
      );
    } catch (e) {
      showStatus(els.status, e.message, true);
    }
  })
);

$("btnSample1").addEventListener("click", () => {
  els.inputText.value = "ababa";
  els.dictSize.value = "4096";
  els.decodeSize.value = "4096";
});

$("btnSample2").addEventListener("click", () => {
  els.inputText.value = "TOBEORNOTTOBEORTOBEORNOT";
  els.dictSize.value = "4096";
  els.decodeSize.value = "4096";
});

$("btnSample3").addEventListener("click", () => {
  els.inputText.value = "aaaaaaaaaaaaaaaa";
  els.dictSize.value = "32";
  els.decodeSize.value = "32";
});
