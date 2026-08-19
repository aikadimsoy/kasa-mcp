# kasa/src/mcp_server/server.py

"""
MCP (Model Context Protocol) sunucusunu çalıştıran ana dosya.
Bu sunucu, localhost üzerinde bir HTTP sunucusu başlatır ve
ajanların Kasa (Vault) ile güvenli bir şekilde etkileşime girmesini
sağlayan araçları (tools) bir API üzerinden sunar.
"""

import os
import time
import hashlib
import secrets
import sqlite3
import asyncio
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from fastapi.staticfiles import StaticFiles

from ..vault.database import Vault
from .tools import VaultTools
from ..config import load_config, get_or_create_bearer_token
import pathlib

# -- Pydantic Modelleri (API şeması için) --

class ToolCall(BaseModel):
    tool_name: str
    parameters: Dict[str, Any]

class ExecuteToolRequest(BaseModel):
    tool_calls: List[ToolCall]
    # Turkce not: bu alan artik YETKI KAYNAGI DEGIL. Etkin kimlik token'dan cozulur
    # (resolve_agent). Alan gonderilirse yalnizca BEYAN sayilir ve bagli kimlikle
    # celisiyorsa istek 403 ile reddedilir. Zorunluluktan cikarildi cunku dogru
    # istemcinin artik onu gondermesine gerek yok; geriye-uyum icin kabul ediliyor.
    agent_id: Optional[str] = Field(
        default=None,
        description="İsteğe bağlı beyan. Yetki token'dan çözülür; uyuşmazsa 403.",
    )

class ToolResult(BaseModel):
    tool_name: str
    result: Dict[str, Any]

class ExecuteToolResponse(BaseModel):
    results: List[ToolResult]

class SimpleToolRequest(BaseModel):
    tool: str
    # Turkce not: varsayilan "browser_extension" KALDIRILDI. Bir varsayilan kimlik,
    # hic token'i olmayan cagriya sessizce bir kimlik verirdi; kimlik artik yalnizca
    # token'dan gelir. None = beyan yok = bagli kimlik kullanilir.
    agent_id: Optional[str] = None
    params: Dict[str, Any] = {}

# -- Bağımlılıklar (Dependencies) --

# Config önce yüklenir — VAULT_PATH ve token burada belirlenir.
# KASA_CONFIG env (varsa) onceliklidir -> paketlenmis app config'i %APPDATA%\KASA'ya yonlendirir
# (frozen bundle icindeki salt-okunur kasa.toml yerine kalici, yazilabilir konum).
_CONFIG_PATH = pathlib.Path(os.environ.get("KASA_CONFIG") or (pathlib.Path(__file__).parent.parent.parent / "kasa.toml"))
_cfg = load_config(_CONFIG_PATH)
_BEARER_TOKEN = get_or_create_bearer_token(_cfg, _CONFIG_PATH)
_ALLOWED_ORIGINS = _cfg["server"]["allowed_origins"]

_vault_path_raw = os.environ.get("KASA_VAULT_PATH") or _cfg["vault"]["path"]
VAULT_PATH = os.path.expanduser(_vault_path_raw)
VAULT_INSTANCE = Vault(vault_path=VAULT_PATH)

RESERVED_AGENT_IDS = {"system"}
PUBLIC_TOOLS = {"event_ingest", "profile_read", "profile_write", "forget", "audit_read", "prune_expired_events"}

# DEBI-0: ajan-basi debi ust-siniri (halusinasyon-dongusu freni). audit_checkpoint /
# audit_archive PUBLIC_TOOLS'a bilerek EKLENMEDI: arsivleme sahibin/bakimin isidir,
# ag katmanindan cagirilamaz (deny-by-default ile tutarli).
from .ratelimit import RateLimiter
RATE_LIMITER = RateLimiter(capacity=60, refill_per_sec=1.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama ömrü: vault bağla, şema kur, kapat."""
    from ..vault.schema import ALL_TABLES, ALL_INDEXES
    VAULT_INSTANCE.connect()
    conn = VAULT_INSTANCE.get_connection()
    for sql in ALL_TABLES + ALL_INDEXES:
        conn.execute(sql)
    
    # browser agent icin events:write otomatik izni (startup)
    #
    # Turkce not (kimlik baglamadan SONRA bu satirin anlami DEGISTI): eskiden bu otomatik
    # izin, F-IMP'in siddetini belirleyen sey idi -- kimlik istemci beyani oldugu icin
    # GECERLI BIR TOKENI OLAN HERKES agent_id="browser" deyip bu yazma iznini devralabiliyordu.
    # Artik kimlik token'a bagli; "browser" kimligine ancak ona BAGLI bir token'la
    # ulasilir. Boyle bir token uretilmediyse bu izin ATILDIR (kimse o kimlige buruneme).
    # Satir, tarayici token'i uretildiginde onun calismasi icin duruyor.
    conn.execute(
        "INSERT OR IGNORE INTO permissions (agent_id, scope, granted_at) VALUES (?, ?, ?)",
        ("browser", "events:write", time.time())
    )
    conn.commit()
    
    yield
    VAULT_INSTANCE.close()

def get_vault() -> Vault:
    """FastAPI bağımlılığı: Vault nesnesini döndürür."""
    return VAULT_INSTANCE

# -- FastAPI Uygulaması --

app = FastAPI(
    title="Project KASA MCP Server",
    description="Ajanlar için yerel, güvenli hafıza kasası.",
    version="0.1.0",
    lifespan=lifespan,
)

# Self-hosted fontlar ve statik varlıklar (tarayıcı toolbar'ı kullanır)
_ASSETS_DIR = pathlib.Path(__file__).parent.parent.parent / "assets"
if _ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# --- G2: Host-header guard (DNS-rebinding defense) ---
# EN: reject any request whose Host is not loopback. A DNS-rebinding page rebinds its own
# origin to 127.0.0.1 and sends the ATTACKER's Host; validating Host defeats it. This is the
# server-side twin of the mcp_adapter urlparse loopback guard, and the MCP spec now REQUIRES
# such protection. Port and IPv6 brackets are stripped before matching; an empty Host
# (HTTP/1.0) is allowed since rebinding relies on a resolvable hostname. Extra hosts
# (reverse-proxy / Tailscale) may be opted in via KASA_ALLOWED_HOSTS (comma list, no wildcard).
# Turkce not: ozel fonksiyon (TrustedHostMiddleware degil) cunku env'i ISTEK BASINA okur
# -> import-zamani sirasindan bagimsiz; ayrica IPv6/port'u dogru ayiklar. Test istemcisi
# "testserver" Host'u yollar; conftest onu KASA_ALLOWED_HOSTS'a ekleyerek suiti kirmaz.
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _host_allowed(host_header: str) -> bool:
    h = (host_header or "").strip()
    if not h:
        return True
    if h.startswith("["):
        h = h[1:].split("]")[0]          # [::1]:8780 -> ::1
    elif h.count(":") == 1:
        h = h.split(":")[0]              # 127.0.0.1:8780 -> 127.0.0.1
    h = h.lower()
    if h in _LOOPBACK_HOSTS:
        return True
    extra = os.environ.get("KASA_ALLOWED_HOSTS", "")
    return h in {x.strip().lower() for x in extra.split(",") if x.strip()}


@app.middleware("http")
async def _host_guard(request: Request, call_next):
    """Runs outermost (added after CORS): reject non-loopback Host before any handler."""
    if not _host_allowed(request.headers.get("host", "")):
        return JSONResponse(
            status_code=400,
            content={"detail": "Geçersiz Host başlığı; yalnızca loopback kabul edilir."},
        )
    return await call_next(request)

# Bearer token authentication için gerekli olan dependency'yi tanımlayalım
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Security

_security = HTTPBearer()

#: Identity assigned to the legacy shared token. It is a real identity like any other:
#: deny-by-default, no auto-granted scopes. The owner grants what it needs, deliberately.
LEGACY_AGENT_ID = os.environ.get("KASA_LEGACY_AGENT_ID", "legacy")


def _token_digest(token: str) -> str:
    """SHA-256 of a bearer token — the lookup key stored in `agent_tokens`."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _lookup_bound_agent(token: str) -> Optional[str]:
    """Identity bound to `token`, or None if no active binding exists.

    Uses its OWN short-lived connection on purpose. Measured reason (live uvicorn, real
    socket): this function runs inside a FastAPI *sync* dependency, which Starlette
    offloads to a threadpool worker, while VAULT_INSTANCE's sqlite connection belongs to
    the event-loop thread. sqlite3 objects are thread-bound, so reusing that connection
    raised ProgrammingError on EVERY request -- and an earlier `except Exception: pass`
    here swallowed it, silently dropping every caller onto the legacy-token path. Net
    effect: a correctly issued bound token got HTTP 401, and the impersonation refusal we
    observed was produced by the wrong mechanism (legacy != claimed), not by identity
    resolution. Unit tests missed it because the fixture builds the vault in the test's
    own thread.

    Turkce not: buradaki DERS "hatayi yutma"dir. Kimlik yolunda genis `except: pass`,
    altyapi arizasini "boyle bir token yok" cevabina cevirir; sistem kapali kalir ama
    SESSIZ bozulur. Uc hal ayrilir:
      - satir bulundu            -> kimlik (eslesme yoksa None; token bilinmiyor demektir)
      - tablo YOK (no such table)-> None. MESRU hal: lifespan'siz/taze vault (or. birim
                                    testleri) veya migration oncesi. Legacy karsilastirmasina
                                    duser -> YANLIS token 401, legacy bearer LEGACY_AGENT_ID.
      - depo OKUNAMIYOR (kilit/   -> 503 FAIL-CLOSED. Karar verilemez; tahmin etme.
        bozuk dosya)
    NEDEN "no such table" 503 DEGIL (sahip red-team notu tekrar analiz): tabloyu KAYBETMEK
    kimseyi YUKSELTMEZ -> bagli token'lar cozulemez ve legacy'e duser; legacy-olmayan token
    401 alir, kimlik KAZANMAZ. Tek yukseltme kolu KASA_LEGACY_AGENT_ID env'idir (A4 config),
    tablo degil. Dolayisiyla "no such table"i 503 yapmak MESRU davranisi kirar (lifespan'siz
    kosum) ve karsiliginda bir yukseltme yolu KAPATMAZ.
    """
    try:
        conn = sqlite3.connect(VAULT_INSTANCE.db_path, timeout=5.0)
    except Exception:
        raise HTTPException(status_code=503, detail="Kimlik deposuna erişilemiyor.")
    try:
        row = conn.execute(
            "SELECT agent_id FROM agent_tokens WHERE token_hash=? AND revoked_at IS NULL",
            (_token_digest(token),),
        ).fetchone()
        return row[0] if row is not None else None
    except sqlite3.OperationalError as exc:
        # "no such table" MESRU haldir (lifespan'siz/taze vault) ve YUKSELTME saglamaz
        # (yukaridaki docstring analizine bak) -> None don, legacy karsilastirmasina dussun.
        if "no such table" in str(exc).lower():
            return None
        # Gercek okuma arizasi (kilit / bozuk dosya): KARAR VERILEMEZ -> fail-closed 503.
        raise HTTPException(status_code=503, detail="Kimlik deposu okunamadı.")
    finally:
        conn.close()


def resolve_agent(credentials: HTTPAuthorizationCredentials = Security(_security)) -> str:
    """Return the agent identity BOUND to the presented token. Never trusts the request body.

    Turkce not: F-IMP'in kok-neden fix'i burasi. Eskiden kimlik istek GOVDESINDEN
    geliyordu ve dogrulanmiyordu -> token sahibi baska bir ajanin kimligine burunup
    onun iznini devralabiliyordu. Artik kimlik TOKEN'DAN cozulur:

      1) `agent_tokens` tablosunda hash'i eslesen etkin bir kayit varsa -> o kimlik
      2) yoksa ve token eski PAYLASILAN token ise -> LEGACY_AGENT_ID
      3) hicbiri degilse -> 401

    (2) numarali yol geriye-uyum icindir ve bir kacak DEGILDIR: eski token artik tek bir
    kimlige baglanmistir, istedigi kimligi soyleyemez. O kimligin de VARSAYILAN-RED
    disinda hicbir izni yoktur; sahip `tools/grant_agent_scope.py` ile bilerek verir.

    DURUST SINIR: bu, ayni OS kullanicisi olarak calisan koda karsi bir sinir DEGILDIR
    (o kod token dosyasini zaten okuyabilir; docs/THREAT_MODEL.md dusman sinifi A).
    Kapatilan sey, GECERLI BIR TOKENI olan caginin BASKA bir kimlige burunmesidir.
    """
    presented = credentials.credentials

    # 1) Bagli ajan token'i mi?
    bound = _lookup_bound_agent(presented)
    if bound is not None:
        return bound

    # 2) Eski paylasilan token -> tek ve sabit bir kimlik.
    if secrets.compare_digest(presented, _BEARER_TOKEN):
        return LEGACY_AGENT_ID

    # 3) Taninmayan token.
    raise HTTPException(status_code=401, detail="Geçersiz token.")


def verify_token(credentials: HTTPAuthorizationCredentials = Security(_security)) -> str:
    """Auth gate. Returns the resolved identity so callers that need it can capture it.

    Turkce not: ajan araç uclari (execute_tool/ingest) bunu KAPI olarak kullanir; kimlige
    ihtiyaci olan donusu yakalar. NOT: owner-UI uclari (dashboard/agent/terms) artik bunu
    KULLANMAZ -> require_owner kullanir. Sebep: verify_token HERHANGI gecerli bearer'i kabul
    eder; owner yuzeyi 'gecerli' degil 'SAHIP' ister (bkz. require_owner, F-OWNER-SCOPE).
    """
    return resolve_agent(credentials)


def require_owner(credentials: HTTPAuthorizationCredentials = Security(_security)) -> None:
    """Owner-only gate (F-OWNER-SCOPE fix). Owner = yapilandirilmis bearer'in sahibi.

    OLCULDU (canli, bagimsiz lab): verify_token HERHANGI gecerli bearer'i kabul ettigi icin,
    BILEREK dusuk-yetkili verilmis bir bagli-ajan token'i owner yuzeylerine ulasti
    (/v1/dashboard/*, /v1/agent/*, /v1/terms/* hepsi HTTP 200). O yuzeyler SAHIBIN'dir;
    'gecerli bir token' degil, SAHIP kimlik-bilgisi istemeli. Sabit-zamanli karsilastirma;
    bir ajan token'i _BEARER_TOKEN'a esit DEGILDIR -> 403.

    Bu, kimlik baglamayi (agent_tokens) GECERSIZ kilmaz; onu TAMAMLAR: kimlik dogru cozulse
    bile owner yuzeyi ayrica SAHIP olmayi arar. Iki ayri kapi, iki ayri kok-neden.
    """
    if not secrets.compare_digest(credentials.credentials, _BEARER_TOKEN):
        raise HTTPException(status_code=403, detail="Bu uç yalnızca sahip içindir.")


# Owner-UI baslatma nonce'u (F-DASH fix): owner token'i dashboard/terms HTML'ine YALNIZCA
# bu nonce'u tasiyan istege gomulur. launch.py bunu okur ve tarayiciyi /dashboard?k=<nonce>
# ile acar; nonce'u olmayan bir ag istemcisi token'SIZ sayfa alir. Surec-basina, yuksek
# entropili, DISKE YAZILMAZ. (OLCULDU: tokensiz GET /dashboard owner token'i sizdiriyordu.)
_LAUNCH_NONCE = secrets.token_urlsafe(32)


def _bound_identity(claimed: Optional[str], resolved: str) -> str:
    """Reject a body-claimed agent_id that disagrees with the token-bound one.

    Turkce not: gövdedeki agent_id artik YETKI KAYNAGI degil, olsa olsa bir BEYANDIR.
    Beyan, bagli kimlikle celisiyorsa istek reddedilir (sessizce duzeltilmez) -- cunku
    sessiz duzeltme, istemcinin yanlis kimlikle is yaptigini gizler ve denetim kaydini
    yanlis okutur. Celiskiyi gormezden gelmek yerine YUZE VURMAK dogru davranistir.
    """
    if claimed is not None and claimed != resolved:
        raise HTTPException(
            status_code=403,
            detail="agent_id token'a bağlı kimlikle uyuşmuyor.",
        )
    return resolved

# Read-only dashboard uclari (aggregate + maskeli; docs/UI_UX_STANDARD.md).
# NOT: include_router bu ortamda (starlette 1.1.0) route kopyalamiyor -> add_api_route.
from ..dashboard.routes import register as _register_dashboard
_register_dashboard(app, get_vault, _BEARER_TOKEN, require_owner, _LAUNCH_NONCE)

# Ajan koprusu uclari (yerel model + read-through-redact araclar; docs/ORCHESTRATOR_SURVEY.md).
# Ayni add_api_route deseni (starlette include_router route dusuruyor).
# require_owner: ajan koprusu (model degistir/chat/race) owner islemidir, ag ajaninin degil.
from ..agent.routes import register as _register_agent
_register_agent(app, get_vault, require_owner)

# -- Endpoints --

@app.post("/v1/execute_tool", response_model=ExecuteToolResponse)
async def execute_tool(
    request: ExecuteToolRequest,
    vault: Vault = Depends(get_vault),
    bound_agent: str = Security(verify_token),  # token -> BAGLI kimlik
):
    """
    Bir veya daha fazla aracı (tool) çalıştırır.
    """
    # Kimlik token'dan gelir; govdedeki beyan yalnizca celiski denetimi icindir.
    agent_id = _bound_identity(request.agent_id, bound_agent)

    if agent_id in RESERVED_AGENT_IDS:
        raise HTTPException(status_code=403, detail="Ajan kimliği mevcut değil.")

    # DEBI-0: her tool_call 1 token. Izin kontrolunden ONCE: reddedilen cagri da is yapar
    # (audit yazar), fren en distaki kapida olmali.
    #
    # Turkce not: kova artik BAGLI kimlige anahtarlaniyor. Eskiden beyan edilen agent_id'ye
    # anahtarliydi -> saldirgan her istekte yeni bir kimlik uydurup her seferinde TAZE bir
    # kova aliyordu (olculdu: donen kimlikle 150 istekte 0 adet 429). Kimlik token'a bagli
    # oldugu icin artik uydurulamaz; hiz siniri ayni kokten onarilir.
    if not RATE_LIMITER.allow(agent_id, cost=float(max(1, len(request.tool_calls)))):
        raise HTTPException(status_code=429, detail="Hız sınırı aşıldı; daha sonra tekrar deneyin.")

    tool_handler = VaultTools(vault, agent_id=agent_id)
    response_results = []

    for tool_call in request.tool_calls:
        tool_name = tool_call.tool_name
        params = tool_call.parameters

        if tool_name not in PUBLIC_TOOLS:
            raise HTTPException(
                status_code=404,
                detail=f"Araç bulunamadı: '{tool_name}'"
            )

        try:
            method = getattr(tool_handler, tool_name)
            # TODO: Asenkron araçları destekle
            result = method(**params)
            response_results.append(ToolResult(tool_name=tool_name, result=result))

        except ValueError as e:
            # L4: gecersiz girdi degeri (orn. TTL araligi, uzunluk) -> 400 (client), 500 DEGIL.
            raise HTTPException(status_code=400, detail=f"'{tool_name}': geçersiz istek: {e}")
        except TypeError as e:
            # Yanlış parametreler için
            raise HTTPException(
                status_code=422,
                detail=f"'{tool_name}' aracı için geçersiz parametreler: {e}"
            )
        except PermissionError as e:
            raise HTTPException(status_code=403, detail=str(e))
        except HTTPException:
            raise
        except Exception:
            # L4: ic detay SIZDIRMA — genel mesaj don, gercek hatayi sunucu-tarafi logla.
            import logging, traceback
            logging.getLogger("kasa.mcp").error("execute_tool iç hata:\n%s", traceback.format_exc())
            raise HTTPException(status_code=500, detail="İç sunucu hatası.")

    return ExecuteToolResponse(results=response_results)

@app.post("/v1/ingest")
async def ingest(
    request: SimpleToolRequest,
    vault: Vault = Depends(get_vault),
    bound_agent: str = Security(verify_token),  # token -> BAGLI kimlik
):
    """Basit tek-araç endpoint'i (browser extension + Native Messaging icin)."""
    # Ayni kural: kimlik token'dan, govde yalnizca beyan (celisirse 403).
    agent_id = _bound_identity(request.agent_id, bound_agent)

    if agent_id in RESERVED_AGENT_IDS:
        raise HTTPException(status_code=403, detail="Ajan kimliği mevcut değil.")

    # DEBI-0: tek-arac endpoint'i de ayni kovadan tuketir (yan kapi birakma).
    if not RATE_LIMITER.allow(agent_id, cost=1.0):
        raise HTTPException(status_code=429, detail="Hız sınırı aşıldı; daha sonra tekrar deneyin.")

    tool_handler = VaultTools(vault, agent_id=agent_id)
    if request.tool not in PUBLIC_TOOLS:
        raise HTTPException(
            status_code=404,
            detail=f"Araç bulunamadı: '{request.tool}'"
        )

    try:
        method = getattr(tool_handler, request.tool)
        # TODO: Asenkron araçları destekle
        result = method(**request.params)
        return {"result": result}

    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Geçersiz istek: {e}")
    except TypeError as e:
        raise HTTPException(status_code=422, detail=f"Geçersiz parametreler: {e}")
    except HTTPException:
        raise
    except Exception:
        # L4: ic detay str(e) SIZDIRMA -> genel mesaj + sunucu-tarafi log.
        import logging, traceback
        logging.getLogger("kasa.mcp").error("ingest iç hata:\n%s", traceback.format_exc())
        raise HTTPException(status_code=500, detail="İç sunucu hatası.")

@app.get("/")
async def health_check():
    """Health check — auth gerektirmez."""
    return {"status": "ok", "version": "0.2.0"}

def start_server(host: str = "127.0.0.1", port: int = 8000):
    print(f"[KASA] MCP sunucusu baslatiliyor: http://{host}:{port}")
    # F-DASH: owner UI'ye erisim launch nonce'u ister. Manuel/dev kosumda launch.py yoksa
    # sahibin URL'yi buradan alabilmesi icin YAZDIR (loopback konsoluna; disari gitmez).
    print(f"[KASA] Owner panosu: http://{host}:{port}/dashboard?k={_LAUNCH_NONCE}")
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    start_server()
