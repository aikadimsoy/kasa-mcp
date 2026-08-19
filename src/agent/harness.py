# kasa/src/agent/harness.py

"""
Agent bridge harness — drives a selected LOCAL model (local model service at 127.0.0.1:11434)
in a bounded tool-calling loop against READ-ONLY masked KASA dashboard functions.

"The model thinks; the harness drives; the deterministic gate has the final say."

SECURITY BOUNDARY (hand-written carve-out — local models do not edit this):
  - Every tool call the model emits passes ``gate.validate_call`` BEFORE execution. A rejected
    call never touches the vault; the reason is traced and fed back to the model as "REJECTED:".
  - The model's tool surface is ONLY the masked dashboard functions (stats.py) — aggregate /
    read-through-redact. Raw VaultTools is never reachable from here.
  - Every tool RESULT fed back to the model is truncated + redact-scanned +
    delimiter-sanitized (defense in depth; the dashboard functions are already masked).
  - Bounded: iterations, wall clock, result size, reply size (gate.* budget).
  - Air-gap: only 127.0.0.1 is ever contacted.

Blocking I/O (`_chat_call`, `list_installed_models`) runs via ``asyncio.to_thread``; vault reads
(`_run_tool`) stay on the calling event-loop thread to preserve SQLite thread affinity.

Turkce not: Ajan koprusu harness'i — secili YEREL modeli sinirli bir arac-cagrisi dongusunde,
SALT-OKUNUR maskeli dashboard fonksiyonlarina karsi surer. Ilke: "Model dusunur; harness surer;
deterministik kapi son sozu soyler." Modelin urettigi her arac cagrisi ONCE gate.validate_call'dan
gecer; gordugu yuzey yalniz maskeli fonksiyonlardir; modele donen her sonuc kirpilir + sir-taranir
+ delimiter-temizlenir. Ag yalniz 127.0.0.1 (hava-boslugu).
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.error
import urllib.request

from . import gate
from ..dashboard import stats
from ..vault.redact import sanitize_untrusted_text
from ..vault.quarantine import neutralize as _neutralize_injection

OLLAMA_BASE = "http://127.0.0.1:11434"

_SYSTEM_PROMPT = (
    "You are KASA's local, privacy-first assistant. KASA is the user's personal memory vault "
    "that runs entirely on their own machine. You may call the provided tools to answer "
    "questions about the user's vault statistics, recent events, and profile. Every piece of "
    "data you receive is ALREADY masked/redacted and aggregated — you will never see raw "
    "secrets, and you must not ask for them. Answer concisely in the user's language. "
    "Never invent data: if the tools do not provide an answer, say so."
)

# JSON-fallback: tool-cagirmayi native desteklemeyen modeller icin ```json{"tool","args"}```.
_JSON_FENCE_RE = re.compile(r"```json\s*\r?\n(.*?)```", re.DOTALL)


def list_installed_models() -> tuple[bool, list[dict]]:
    """Kurulu yerel modelleri dondurur. (service_up, [{name,size}]). BLOCKING (to_thread ile sar)."""
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return False, []
    models = [
        {"name": m.get("name", ""), "size": m.get("size", 0)}
        for m in (data.get("models") or [])
        if m.get("name")
    ]
    return True, models


def _chat_call(model: str, messages: list, tools: list, timeout: int) -> dict:
    """Yerel servis /api/chat (stream:false). BLOCKING. Ulasilamzsa RuntimeError.
    Bu fonksiyon testlerin monkeypatch noktasidir — ADI DEGISMEZ (_chat_call)."""
    body = json.dumps({
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": False,
        "options": {"temperature": 0.1},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        raise RuntimeError(f"model service unreachable ({getattr(e, 'reason', e)})") from None


def _run_tool(vault, name: str, args: dict) -> dict:
    """Gate'ten GECMIS cagriyi maskeli pano fonksiyonuna dagitir. Calan-thread'de kosar
    (SQLite affinity). Yalniz salt-okunur yuzey; kasa_note bayrak-kapali (yazim yok)."""
    if name == "kasa_stats":
        return {"stats": stats.compute_stats(vault)}
    if name == "kasa_recent_events":
        return {"events": stats.recent_events(vault, args["limit"])}
    if name == "kasa_profile":
        return {"profile": stats.profile_entries(vault, args["limit"])}
    if name == "kasa_note":
        # v1: yazim yolu uygulanmadi (owner-gated, bayrakla kapali). Gate zaten kapaliyken
        # buraya birakmaz; savunma-derinligi.
        return {"status": "disabled"}
    raise ValueError(f"unknown tool {name!r}")


def _prepare_result(result: dict) -> str:
    """Araç sonucunu modele geri beslemeden ONCE: JSON serialize -> kirp -> delimiter-sanitize
    -> Faz-3 enjeksiyon-notrleme.
    (Pano fonksiyonlari zaten maskeli; bunlar savunma-derinligi + injection kapisi.)

    Faz-3 (CaMeL Quarantined-LLM izi): tool sonucundaki vault-serbest-metni araç-yetkili modele
    donmeden ONCE deterministik olarak notrlenir -> enjeksiyon-kalibi metin modelin CEVABINI
    yonlendiremez. Not: EYLEM kapisi degil (gate.validate_call her cagriyi zaten deterministik
    keser); bu adim cevap-butunlugu icin savunma-derinligidir."""
    payload = json.dumps(result, ensure_ascii=False)
    if len(payload) > gate.MAX_RESULT_CHARS:
        payload = payload[:gate.MAX_RESULT_CHARS] + "…[truncated]"
    payload = sanitize_untrusted_text(payload)
    payload, _inj_hits = _neutralize_injection(payload)
    return payload


def _extract_calls(msg: dict) -> list[tuple[str, object]]:
    """Model mesajindan (tool_name, raw_args) ciftlerini cikarir. Once native tool_calls;
    yoksa JSON-fence yedegi. Args str ise json.loads dener."""
    calls: list[tuple[str, object]] = []
    for tc in (msg.get("tool_calls") or []):
        fn = tc.get("function") or {}
        name = fn.get("name") or ""
        raw = fn.get("arguments")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except Exception:
                raw = {}
        calls.append((name, raw if raw is not None else {}))
    if calls:
        return calls
    # Native yoksa: ```json{"tool": "...", "args": {...}}``` yedegi.
    content = msg.get("content") or ""
    m = _JSON_FENCE_RE.search(content)
    if m:
        try:
            obj = json.loads(m.group(1))
            if isinstance(obj, dict) and obj.get("tool"):
                calls.append((obj["tool"], obj.get("args") or {}))
        except Exception:
            pass
    return calls


async def run_chat(vault, model: str, message: str, history: list | None,
                   allow_notes: bool = False) -> dict:
    """Sinirli araç-cagirma dongusu. Doner:
    {reply, model, iterations, elapsed_ms, trace:[{step,type,tool?,detail}]}."""
    messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": message})

    tools = gate.chat_tool_schemas(allow_notes)
    start = time.monotonic()
    trace: list[dict] = []
    iterations = 0
    reply = ""

    while iterations < gate.MAX_ITERATIONS:
        if time.monotonic() - start > gate.TOTAL_TIMEOUT_S:
            trace.append({"step": iterations, "type": "timeout", "detail": "total budget exceeded"})
            break

        resp = await asyncio.to_thread(_chat_call, model, messages, tools, gate.CALL_TIMEOUT_S)
        msg = resp.get("message") or {}
        calls = _extract_calls(msg)

        if not calls:
            content = msg.get("content") or ""
            reply = content[:gate.MAX_REPLY_CHARS]
            trace.append({"step": iterations, "type": "model_reply", "detail": f"{len(content)} chars"})
            break

        # Asistan tur'unu (tool_calls dahil) gecmise ekle -> model tekrar sormaz.
        messages.append({"role": "assistant", "content": msg.get("content") or "",
                         "tool_calls": msg.get("tool_calls") or []})
        iterations += 1

        for name, raw_args in calls:
            ok, norm_or_reason = gate.validate_call(name, raw_args, allow_notes)
            if not ok:
                trace.append({"step": iterations, "type": "gate_reject",
                              "tool": name, "detail": norm_or_reason})
                messages.append({"role": "tool", "content": "REJECTED: " + str(norm_or_reason)})
                continue
            try:
                result = _run_tool(vault, name, norm_or_reason)  # loop thread: SQLite affinity
            except Exception as e:  # beklenmedik: gate'ten gecti ama calisma hatasi
                trace.append({"step": iterations, "type": "tool_error", "tool": name, "detail": str(e)})
                messages.append({"role": "tool", "content": "ERROR: " + str(e)})
                continue
            payload = _prepare_result(result)
            trace.append({"step": iterations, "type": "tool_call",
                          "tool": name, "detail": f"{len(payload)} chars"})
            messages.append({"role": "tool", "content": payload})

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return {"reply": reply, "model": model, "iterations": iterations,
            "elapsed_ms": elapsed_ms, "trace": trace}


async def run_race(vault, models: list[str], message: str, history: list | None,
                   allow_notes: bool = False) -> dict:
    """Yaris Modu: ayni soruyu birden cok YEREL modele sorar, sonuclari yan yana dondurur.
    Her model kendi run_chat'inde izole kosar; biri patlarsa {model,error} doner, digerleri
    surer. Es-zamanli (yerel servis GPU'da siraya alir). Ayni gate + redact siniri her modelde.
    Doner: {results: [{model, reply, iterations, elapsed_ms, trace} | {model, error}]}."""
    async def _one(model: str) -> dict:
        try:
            return await run_chat(vault, model, message, history, allow_notes)
        except Exception as e:  # bir modelin cokmesi yarisi bozmaz
            return {"model": model, "error": str(e)}

    results = await asyncio.gather(*[_one(m) for m in models])
    return {"results": list(results)}
