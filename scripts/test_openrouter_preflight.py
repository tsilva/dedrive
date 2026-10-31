"""Offline credential-boundary tests; curl is always replaced with a fake."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

SCRIPT = Path(__file__).with_name("openrouter-preflight.sh")
FAKE_KEY = "dedrive-fake-test-key+/=_-."


class PreflightTests(unittest.TestCase):
    def run_preflight(self, key=None, mode="success", trace=False, allexport=False,
                      base_url="http://127.0.0.1:8082/api/v1"):
        with tempfile.TemporaryDirectory(prefix="dedrive-preflight-") as directory:
            scratch = Path(directory)
            capture = scratch / "capture.json"
            curl = scratch / "curl"
            curl.write_text(
                f"#!{sys.executable}\n"
                "import json, os, pathlib, sys\n"
                "data = {'argv': sys.argv[1:], 'stdin': sys.stdin.read(),\n"
                "        'key_in_environment': 'AGENTBRIDGE_API_KEY' in os.environ,\n"
                "        'local_key_exported': 'dedrive_gateway_key' in os.environ}\n"
                "pathlib.Path(os.environ['CURL_TEST_CAPTURE']).write_text(json.dumps(data))\n"
                "mode = os.environ['CURL_TEST_MODE']\n"
                "if mode == 'transport-error':\n"
                "    print('reflected fake credential: ' + data['stdin'], file=sys.stderr)\n"
                "    sys.exit(7)\n"
                "print('401' if mode == 'http-error' else\n"
                "      'reflected-invalid-status' if mode == 'invalid-status' else '200', end='')\n",
                encoding="utf-8",
            )
            curl.chmod(0o700)
            environment = {
                "PATH": str(scratch) + os.pathsep + os.defpath,
                "TMPDIR": str(scratch),
                "CURL_TEST_CAPTURE": str(capture),
                "CURL_TEST_MODE": mode,
                "AGENTBRIDGE_BASE_URL": base_url,
                "dedrive_gateway_key": "exported-fake-parent-value",
            }
            if key is not None:
                environment["AGENTBRIDGE_API_KEY"] = key
            command = [
                "/bin/bash", *(["-x"] if trace else []),
                *(["-a"] if allexport else []), str(SCRIPT),
            ]
            result = subprocess.run(command, env=environment, capture_output=True, text=True)
            data = json.loads(capture.read_text()) if capture.exists() else None
            return result, data

    def test_no_credential_omits_authorization(self):
        for key in [None, ""]:
            with self.subTest(key=key):
                result, data = self.run_preflight(key)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(data["stdin"], "")
                self.assertNotIn("--header", data["argv"])

    def test_credential_uses_stdin_without_argv_environment_or_trace_leaks(self):
        for trace, allexport in [(False, False), (True, False), (False, True), (True, True)]:
            with self.subTest(trace=trace, allexport=allexport):
                result, data = self.run_preflight(FAKE_KEY, trace=trace, allexport=allexport)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(data["stdin"], f"Authorization: Bearer {FAKE_KEY}\n")
                self.assertNotIn(FAKE_KEY, " ".join(data["argv"]))
                self.assertFalse(data["key_in_environment"])
                self.assertFalse(data["local_key_exported"])
                self.assertNotIn(FAKE_KEY, result.stdout + result.stderr)
                self.assertEqual(data["argv"][0], "-q")
                self.assertIn("/dev/null", data["argv"])
                self.assertEqual(data["argv"][-1],
                                 "http://127.0.0.1:8082/api/v1/openrouter/credits")

    def test_control_characters_are_rejected_before_curl(self):
        for control in ["\r", "\n", "\t", "\x7f"]:
            with self.subTest(control=repr(control)):
                result, data = self.run_preflight(FAKE_KEY + control + "injected")
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(data)
                self.assertNotIn(FAKE_KEY, result.stdout + result.stderr)

    def test_failures_do_not_echo_response_or_transport_details(self):
        for mode in ["http-error", "transport-error", "invalid-status"]:
            with self.subTest(mode=mode):
                result, _ = self.run_preflight(FAKE_KEY, mode=mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(FAKE_KEY, result.stdout + result.stderr)
                self.assertNotIn("reflected", result.stdout + result.stderr)

    def test_base_url_cannot_put_credentials_in_curl_arguments(self):
        urls = [
            f"https://user:{quote(FAKE_KEY, safe='')}@gateway.test/api/v1",
            f"https://gateway.test/api/v1?key={FAKE_KEY}",
            f"https://gateway.test/api/v1#{FAKE_KEY}",
            "http://gateway.test/\ninvalid",
        ]
        for url in urls:
            with self.subTest(url=url):
                result, data = self.run_preflight(base_url=url)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(data)
                self.assertNotIn(FAKE_KEY, result.stdout + result.stderr)
                self.assertNotIn(quote(FAKE_KEY, safe=""), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
