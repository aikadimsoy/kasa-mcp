# kasa/src/client.py

"""
KASA - Sovereign AI Memory & Security Client SDK

Dış Python ajanlarının (LangChain, CrewAI, AutoGen, Cursor, Claude Desktop vb.)
KASA Reference Monitor ve Memory Vault ile 1 satırda güvenle konuşmasını sağlayan resmi SDK.

Kullanım:
    from src.client import KasaClient

    kasa = KasaClient(token="your_bearer_token")
    kasa.ingest(source="cli", type="user_action", content={"action": "build"})
    profile = kasa.get_profile("user.*", reason="context_assembly")
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class KasaClient:
    def __init__(self, base_url: str = "http://127.0.0.1:8000", token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """KASA Reference Monitor /v1/execute_tool uç noktasına yetkili çağrı yapar."""
        url = f"{self.base_url}/v1/execute_tool"
        payload = {
            "tool": tool_name,
            "arguments": arguments,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                return res_data.get("result", res_data)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="ignore")
            raise PermissionError(f"KASA Error (HTTP {e.code}): {err_body}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to KASA daemon at {self.base_url}: {e}")

    def ingest(self, source: str, type: str, content: Dict[str, Any], ttl_days: int = 30) -> Dict[str, Any]:
        """Ham bir olayı (Tier 1 Event) KASA'ya yazar."""
        return self._call("event_ingest", {
            "source": source,
            "type": type,
            "content": content,
            "ttl_days": ttl_days,
        })

    def get_profile(self, scope: str, reason: str) -> Dict[str, Any]:
        """Damıtılmış profil verilerini (Tier 2 Profile) bağlamsal bilet ile okur."""
        return self._call("profile_read", {
            "scope": scope,
            "reason": reason,
        })

    def set_profile(self, key: str, value: Any, provenance: List[int]) -> Dict[str, Any]:
        """Profil hafızasına doğrulanmış bilgi yazar (Enjeksiyon tespit edilirse karantinaya alınır)."""
        return self._call("profile_write", {
            "key": key,
            "value": value,
            "provenance": provenance,
        })

    def forget(self, topic: str) -> Dict[str, Any]:
        """Unutulma hakkını (GDPR T5) tetikleyerek konuya ait tüm verileri ve arama indekslerini siler."""
        return self._call("forget", {
            "topic": topic,
        })
