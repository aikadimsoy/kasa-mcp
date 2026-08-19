# kasa/src/agent/routes.py

"""
Agent bridge FastAPI endpoints. Registered like src/dashboard/routes.py: this environment's
starlette silently drops include_router routes, so we call ``app.add_api_route`` directly.
JSON handlers are ``async def`` (SQLite connection lives on the event-loop thread).

Endpoints (all bearer-protected):
  GET  /v1/agent/models  -> {service_up, models:[{name,size}], selected}
  POST /v1/agent/model   -> {ok, selected}  | 400 (allow-list) / 503 (service down)
  POST /v1/agent/chat    -> {reply, model, iterations, elapsed_ms, trace} | 400/409/503

Security: model selection is validated by gate.validate_model_name (regex + installed
membership); chat input/history by gate.validate_message/validate_history; a single in-flight
chat is enforced by an asyncio.Lock (409 on concurrency). The harness applies the tool gate.

Turkce not: Ajan koprusunun HTTP uc noktalari (hepsi bearer-korumali). Model secimi
gate.validate_model_name (regex + kurulu-model uyeligi) ile, sohbet girdisi/gecmisi gate ile
dogrulanir; ayni anda TEK sohbet asyncio.Lock ile zorlanir (eszamanlilikta 409). Arac
kapisini harness uygular; bu katman yalniz dogrulanmis istegi ona devreder.
"""

from __future__ import annotations

import asyncio

from fastapi import Depends, HTTPException, Security
from pydantic import BaseModel

from . import gate, harness, store

# Sohbet tek-akista (kaynak korumasi + deterministik trace); ikinci istek 409.
_chat_lock = asyncio.Lock()


class ModelSelectRequest(BaseModel):
    name: str


class ChatRequest(BaseModel):
    message: str
    history: list | None = None


class RaceRequest(BaseModel):
    message: str
    models: list
    history: list | None = None


def register(app, get_vault, require_owner) -> None:
    """Ajan uclarini app uzerine dogrudan kaydeder (add_api_route; dairesel import yok).

    Turkce not: imza `verify_token` -> `require_owner` oldu. Ajan koprusu (model degistir,
    chat, race, model listesi) OWNER islemidir; ag ajaninin yuzeyi degil. verify_token
    HERHANGI gecerli bearer'i kabul ederdi ve dusuk-yetkili token bu uclara ulasirdi
    (canli olcum: /v1/agent/models 200). require_owner yalnizca SAHIP bearer'ini gecirir.
    """

    async def agent_models(_=Security(require_owner)):
        service_up, models = await asyncio.to_thread(harness.list_installed_models)
        return {"service_up": service_up, "models": models, "selected": store.get_selected_model()}

    async def agent_select_model(body: ModelSelectRequest, _=Security(require_owner)):
        service_up, models = await asyncio.to_thread(harness.list_installed_models)
        if not service_up:
            raise HTTPException(status_code=503, detail="local model service is not running")
        ok, reason = gate.validate_model_name(body.name, {m["name"] for m in models})
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        store.set_selected_model(body.name)
        return {"ok": True, "selected": body.name}

    async def agent_chat(body: ChatRequest, vault=Depends(get_vault), _=Security(require_owner)):
        ok, reason = gate.validate_message(body.message)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        ok, reason = gate.validate_history(body.history)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        if _chat_lock.locked():
            raise HTTPException(status_code=409, detail="another chat is in progress")
        async with _chat_lock:
            model = store.get_selected_model()
            try:
                return await harness.run_chat(vault, model, body.message, body.history)
            except RuntimeError as e:
                raise HTTPException(status_code=503, detail=str(e))

    async def agent_race(body: RaceRequest, vault=Depends(get_vault), _=Security(require_owner)):
        ok, reason = gate.validate_message(body.message)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        ok, reason = gate.validate_history(body.history)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        service_up, installed = await asyncio.to_thread(harness.list_installed_models)
        if not service_up:
            raise HTTPException(status_code=503, detail="local model service is not running")
        ok, models_or_reason = gate.validate_race_models(body.models, {m["name"] for m in installed})
        if not ok:
            raise HTTPException(status_code=400, detail=models_or_reason)
        if _chat_lock.locked():
            raise HTTPException(status_code=409, detail="another chat/race is in progress")
        async with _chat_lock:
            try:
                return await harness.run_race(vault, models_or_reason, body.message, body.history)
            except RuntimeError as e:
                raise HTTPException(status_code=503, detail=str(e))

    app.add_api_route("/v1/agent/models", agent_models, methods=["GET"], tags=["agent"])
    app.add_api_route("/v1/agent/model", agent_select_model, methods=["POST"], tags=["agent"])
    app.add_api_route("/v1/agent/chat", agent_chat, methods=["POST"], tags=["agent"])
    app.add_api_route("/v1/agent/race", agent_race, methods=["POST"], tags=["agent"])
