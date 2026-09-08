"""Regression for FreeRDP's native certificate fingerprint wire format."""
import unittest
from unittest.mock import patch

from rdp import pam_rdp


class NativeFingerprintTest(unittest.TestCase):
    def test_native_colon_bytes_preserve_nla_and_certificate_validation(self):
        target = dict(hostname="windows.invalid", port=3389, username="test",
                      domain="", password="synthetic-test-value",
                      cert_fingerprint="sha256:" + "ABCDEF01" * 8)
        with patch.object(pam_rdp, "windows_target", return_value=target):
            params = pam_rdp.connection_spec(
                "a" * 32, {"RDP_PASSWORD": "synthetic-placeholder"})["parameters"]
        self.assertEqual(params["cert-fingerprints"],
                         "sha256:" + ":".join(["ab", "cd", "ef", "01"] * 8))
        self.assertEqual(params["security"], "nla")
        self.assertEqual(params["ignore-cert"], "false")
        self.assertEqual(params["cert-tofu"], "false")


if __name__ == "__main__":
    unittest.main()
