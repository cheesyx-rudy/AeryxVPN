import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "usual-sub" / "legacy"))
import proxy_parser  # noqa: E402


class XrayOutboundTests(unittest.TestCase):
    def test_vless_reality_builds_expected_stream_settings(self):
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?encryption=none&security=reality&pbk=abc123&sni=example.com"
            "&fp=chrome&sid=abcd&type=tcp"
        )
        outbound = proxy_parser.build_xray_outbound(uri)
        self.assertEqual(outbound["protocol"], "vless")
        self.assertEqual(outbound["streamSettings"]["security"], "reality")
        self.assertEqual(outbound["streamSettings"]["realitySettings"]["publicKey"], "abc123")

    def test_vless_websocket_tls(self):
        uri = (
            "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            "?encryption=none&security=tls&sni=example.com&type=ws"
            "&path=%2Fws&host=cdn.example.com"
        )
        outbound = proxy_parser.build_xray_outbound(uri)
        self.assertEqual(outbound["streamSettings"]["network"], "ws")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["path"], "/ws")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["headers"]["Host"], "cdn.example.com")

    def test_vmess_json_link(self):
        payload = {
            "v": "2", "ps": "test", "add": "example.com", "port": "443",
            "id": "11111111-1111-4111-8111-111111111111", "aid": "0",
            "scy": "auto", "net": "ws", "type": "none", "host": "example.com",
            "path": "/ws", "tls": "tls", "sni": "example.com",
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        outbound = proxy_parser.build_xray_outbound("vmess://" + encoded)
        self.assertEqual(outbound["protocol"], "vmess")
        self.assertEqual(outbound["streamSettings"]["network"], "ws")
        self.assertEqual(outbound["streamSettings"]["security"], "tls")

    def test_shadowsocks_sip002(self):
        outbound = proxy_parser.build_xray_outbound("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388")
        self.assertEqual(outbound["protocol"], "shadowsocks")
        self.assertEqual(outbound["settings"]["servers"][0]["method"], "aes-256-gcm")

    def test_hysteria2_is_not_misreported_as_xray_valid(self):
        with self.assertRaisesRegex(ValueError, "cannot validate protocol"):
            proxy_parser.build_xray_outbound("hysteria2://password@example.com:443?sni=example.com")


if __name__ == "__main__":
    unittest.main()
