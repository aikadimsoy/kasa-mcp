import sys, os, sqlite3, tempfile, shutil, unittest
import os as _os
# Turkce not: sabit "d:/kasa" YERINE bu dosyanin konumundan turetilir
# (tests/ -> parent = depo koku). Sabit yol, depoyu klonlayan herkeste ve
# CI kosucusunda bu testi kirardi.
_KASA_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
sys.path.insert(0, _KASA_ROOT)
from src.vault.database import Vault
from src.vault.audit import AuditChain
from src.vault.schema import CREATE_AUDIT_TABLE
from src.mcp_server.tools import VaultTools

class TestVault(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.vault = Vault(vault_path=self.tmpdir)
        self.vault.connect()
        self.conn = self.vault.get_connection()

    def tearDown(self):
        self.vault.close()
        shutil.rmtree(self.tmpdir)

    def test_schema_created(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        expected_tables = ['events', 'profile', 'permissions', 'audit']
        for t in expected_tables:
            self.assertIn(t, tables)

    def test_write_and_read_event(self):
        tools = VaultTools(self.vault, agent_id="system")
        result = tools.event_ingest("test", "test_type", {"key": "value"}, ttl_days=30)
        self.assertEqual(result["status"], "success")
        self.assertIn("event_id", result)

class TestAuditChain(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(CREATE_AUDIT_TABLE)
        self.conn.commit()
        self.chain = AuditChain(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_record_and_verify(self):
        agent_id = "test_agent"
        action = "test_action"
        details_dict = {"detail": "test"}
        entry_hash1 = self.chain.record(agent_id, action, details_dict)
        entry_hash2 = self.chain.record(agent_id, action, details_dict)
        entry_hash3 = self.chain.record(agent_id, action, details_dict)
        self.assertTrue(self.chain.verify_chain())

    def test_tamper_detected(self):
        agent_id = "test_agent"
        action = "test_action"
        details_dict = {"detail": "test"}
        entry_hash1 = self.chain.record(agent_id, action, details_dict)
        cursor = self.conn.cursor()
        cursor.execute("UPDATE audit SET action='tampered' WHERE id=1")
        self.conn.commit()
        self.assertFalse(self.chain.verify_chain())

class TestVaultTools(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.vault = Vault(vault_path=self.tmpdir)
        self.vault.connect()
        self.tools = VaultTools(self.vault, agent_id="system")

    def tearDown(self):
        self.vault.close()
        shutil.rmtree(self.tmpdir)

    def test_event_ingest(self):
        result = self.tools.event_ingest("test", "test_type", {"key": "value"}, ttl_days=30)
        self.assertEqual(result["status"], "success")
        self.assertIn("event_id", result)
        self.assertIsInstance(result["event_id"], int)

    def test_profile_write_read(self):
        key = "test_key"
        value = "test_value"
        provenance = "test_provenance"
        result = self.tools.profile_write(key, value, provenance)
        self.assertEqual(result["status"], "success")
        result = self.tools.profile_read("*", reason="test_audit")
        self.assertEqual(result["status"], "success")
        self.assertIn(key, [row["key"] for row in result["data"]])

    def test_forget(self):
        key = "test_key"
        value = "test_value"
        provenance = "test_provenance"
        self.tools.profile_write(key, value, provenance)
        result = self.tools.forget(key)
        self.assertEqual(result["status"], "success")
        result = self.tools.profile_read("*", reason="test_audit")
        self.assertNotIn(key, [row["key"] for row in result["data"]])

    def test_audit_read(self):
        result = self.tools.audit_read(start_index=0, count=10)
        self.assertEqual(result["status"], "success")
        self.assertIn("records", result)

class TestMCPAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tempfile
        cls._tmpdir = tempfile.mkdtemp()
        os.environ["KASA_VAULT_PATH"] = cls._tmpdir
        # Server modülü ilk import'ta vault yolunu okur — env set edildikten sonra import
        import importlib, src.mcp_server.server as _srv
        importlib.reload(_srv)
        from fastapi.testclient import TestClient
        cls.client = TestClient(_srv.app, raise_server_exceptions=False)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("KASA_VAULT_PATH", None)
        shutil.rmtree(cls._tmpdir, ignore_errors=True)

    def test_ingest_no_token_rejected(self):
        """Token olmadan /v1/ingest erişimi reddedilmeli."""
        resp = self.client.post("/v1/ingest", json={
            "tool": "event_ingest", "agent_id": "test", "params": {}
        })
        self.assertIn(resp.status_code, (401, 403))

    def test_ingest_wrong_token_returns_401(self):
        """Yanlış token 401 döndürmeli."""
        resp = self.client.post(
            "/v1/ingest",
            json={"tool": "event_ingest", "agent_id": "test", "params": {}},
            headers={"Authorization": "Bearer yanlis_token_xyz"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_health_check_no_auth_required(self):
        """GET / auth gerektirmemeli."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "ok")


class TestEncryptedExport(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Boş bir vault oluştur ve birkaç satır ekle
        vault = Vault(vault_path=self.tmpdir)
        vault.connect()
        tools = VaultTools(vault, agent_id="system")
        tools.event_ingest("test", "test_type", {"x": 1}, ttl_days=10)
        tools.profile_write("user.name", "Test Kullanıcı", [1])
        vault.close()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_export_creates_file(self):
        from src.export.encrypt import export_vault
        out = os.path.join(self.tmpdir, "test.kasa")
        result = export_vault(self.tmpdir, "gizli123", out)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["events"], 1)
        self.assertEqual(result["profile"], 1)
        self.assertTrue(os.path.exists(out))

    def test_verify_correct_password(self):
        from src.export.encrypt import export_vault, verify_export
        out = os.path.join(self.tmpdir, "test.kasa")
        export_vault(self.tmpdir, "gizli123", out)
        v = verify_export(out, "gizli123")
        self.assertEqual(v["status"], "success")
        self.assertEqual(v["events"], 1)
        self.assertEqual(v["profile"], 1)
        self.assertEqual(v["version"], 1)

    def test_verify_wrong_password_raises(self):
        from src.export.encrypt import export_vault, verify_export
        out = os.path.join(self.tmpdir, "test.kasa")
        export_vault(self.tmpdir, "gizli123", out)
        with self.assertRaises(ValueError):
            verify_export(out, "yanlis_parola")

    def test_magic_check(self):
        """Bozuk dosya magic hatası vermeli."""
        from src.export.encrypt import verify_export
        bad = os.path.join(self.tmpdir, "bad.kasa")
        with open(bad, "wb") as f:
            f.write(b"NOPE" + b"\x00" * 50)
        with self.assertRaises(ValueError):
            verify_export(bad, "herhangi")


if __name__ == '__main__':
    unittest.main()
