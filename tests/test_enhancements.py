"""Local tests for PoC runner, hash extractor, reverse shell, social OSINT helpers."""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(__file__))
import bootstrap  # noqa: F401

from engines.hash_extractor import (
    extract_hashes_from_text,
    extract_from_env_file,
    write_hashes_file,
)
from engines.poc_runner import PoCRunner
from engines.reverse_shell_prompt import offer_reverse_shell
from engines.social_osint import SocialOSINT


SAMPLE_SHADOW = """root:$6$salt$hashvaluehere1234567890123456789012345678901234567890:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
"""

SAMPLE_ENV = """APP_KEY=base64:abc
DB_PASSWORD=plaintext
ADMIN_HASH=$2y$10$abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTU012
"""


class TestHashExtractor(unittest.TestCase):
    def test_extract_from_shadow(self):
        hashes = extract_hashes_from_text(SAMPLE_SHADOW)
        self.assertGreaterEqual(len(hashes), 1)
        self.assertTrue(any(h.startswith("$6$") for h in hashes))

    def test_extract_from_env_bcrypt(self):
        hashes = extract_hashes_from_text(SAMPLE_ENV)
        self.assertTrue(any(h.startswith("$2y$") for h in hashes))

    def test_write_hashes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            ip = "192.168.1.99"
            os.environ["ENGINE_WORKSPACE"] = os.path.join(tmp, ip)
            path = write_hashes_file(ip, ["$6$aaa$bbb"])
            self.assertTrue(os.path.isfile(path))
            with open(path, encoding="utf-8") as f:
                self.assertIn("$6$aaa$bbb", f.read())
            del os.environ["ENGINE_WORKSPACE"]

    def test_extract_from_env_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False, encoding="utf-8") as f:
            f.write(SAMPLE_ENV)
            path = f.name
        try:
            hashes = extract_from_env_file(path)
            self.assertTrue(len(hashes) >= 1)
        finally:
            os.unlink(path)


class TestPoCRunner(unittest.TestCase):
    def test_discover_and_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            poc_dir = os.path.join(tmp, "new_pocs")
            os.makedirs(poc_dir)
            script = os.path.join(poc_dir, "hikvision_exploit_poc.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write(
                    '"""Hikvision camera exploit POC"""\n'
                    "import argparse\n"
                    'if __name__ == "__main__":\n'
                    "    pass\n"
                )
            runner = PoCRunner("10.0.0.1", 80, poc_dir=poc_dir)
            pocs = runner.discover_pocs()
            self.assertEqual(len(pocs), 1)
            matches = runner.match_pocs("HIKVISION", min_score=2)
            self.assertEqual(len(matches), 1)

    @patch("engines.poc_runner.subprocess.run")
    def test_run_poc_success_marker(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="exploit completed successfully",
            stderr="",
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
            f.write('if __name__ == "__main__": pass\n')
            path = f.name
        try:
            runner = PoCRunner("10.0.0.1")
            result = runner.run_poc(path, timeout=5)
            self.assertTrue(result["success"])
        finally:
            os.unlink(path)


class TestReverseShellPrompt(unittest.TestCase):
    @patch("builtins.input", side_effect=["n"])
    def test_decline_prompt(self, _mock_input):
        self.assertFalse(offer_reverse_shell("test exploit", "10.0.0.1"))

    def test_auto_mode_skips(self):
        self.assertFalse(
            offer_reverse_shell("test", "10.0.0.1", auto_mode=True)
        )


class TestSocialOSINT(unittest.TestCase):
    @patch("engines.social_osint.requests.get")
    def test_truecaller_scrape_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"name": "John Doe"}<title>John Doe | Truecaller</title>'
        mock_get.return_value = mock_resp

        osint = SocialOSINT()
        result = osint._lookup_truecaller("+966501234567")
        self.assertIn(result["status"], ("FOUND", "NOT FOUND", "CHECK MANUALLY"))
        self.assertEqual(result["platform"], "Truecaller")

    @patch("engines.social_osint.requests.get")
    def test_syncme_scrape(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<h1>Ahmed Ali</h1>'
        mock_get.return_value = mock_resp

        osint = SocialOSINT()
        result = osint._lookup_syncme("+966501234567")
        self.assertEqual(result["platform"], "Sync.me")


class TestTelegramExtras(unittest.TestCase):
    def test_detect_email(self):
        from core.telegram_extras import detect_osint_message

        result = detect_osint_message("user@example.com")
        self.assertEqual(result, ("email", "user@example.com"))

    def test_detect_osint_prefix(self):
        from core.telegram_extras import detect_osint_message

        result = detect_osint_message("osint:user testname")
        self.assertEqual(result, ("user", "testname"))

    def test_run_osint_invalid(self):
        from core.telegram_extras import run_osint_action

        msg = run_osint_action("email", "not-an-email")
        self.assertIn("Invalid", msg)


class TestImports(unittest.TestCase):
    def test_import_new_modules(self):
        import engines.hash_extractor  # noqa: F401
        import engines.poc_runner  # noqa: F401
        import engines.reverse_shell_prompt  # noqa: F401


if __name__ == "__main__":
    unittest.main()
