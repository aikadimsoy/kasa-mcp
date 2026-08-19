import socket
import logging

# Orijinal socket metodlarını sakla
_original_socket = socket.socket
_original_create_connection = socket.create_connection

# İzin verilen hedef listesi (localhost ve belli başlı public API'ler)
ALLOW_LIST_HOSTS = {
    "127.0.0.1",
    "localhost",
    "::1",
    "api.github.com"
}

logger = logging.getLogger("kasa.egress")

class EgressBlockedError(Exception):
    pass

def _check_destination(host, port):
    if host not in ALLOW_LIST_HOSTS:
        logger.warning(f"BLOCKED OUTBOUND CONNECTION to {host}:{port}")
        raise EgressBlockedError(f"Egress Guard Blocked Connection to {host}:{port}. Destination is not in the allow-list.")

class GuardedSocket(_original_socket):
    def connect(self, address):
        if isinstance(address, tuple):
            host, port = address
            _check_destination(host, port)
        return super().connect(address)

def _guarded_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *, all_errors=False):
    host, port = address
    _check_destination(host, port)
    return _original_create_connection(address, timeout, source_address, all_errors=all_errors)

def enable_egress_guard():
    """Tüm standart socket bağlantılarını denetler. (L2 Kalkanı)"""
    socket.socket = GuardedSocket
    socket.create_connection = _guarded_create_connection
    logger.info("Egress Guard enabled: outbound network access is now restricted.")

def disable_egress_guard():
    """Egress Guard'ı kapatır (Sadece testler için)."""
    socket.socket = _original_socket
    socket.create_connection = _original_create_connection
