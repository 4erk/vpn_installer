from __future__ import annotations

import base64
import hashlib
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from vpn_installer.interserver_transport import decode_transport_pem, derive_transport_password, generate_transport_identity, validate_transport_identity


class InterserverTransportTests(unittest.TestCase):
    def test_generated_identity_has_matching_certificate_key_and_pin(self) -> None:
        identity = generate_transport_identity()
        certificate_pem = "\n".join(decode_transport_pem(identity["INTERSERVER_HY2_CERTIFICATE_B64"], "certificate")) + "\n"
        private_key_pem = "\n".join(decode_transport_pem(identity["INTERSERVER_HY2_PRIVATE_KEY_B64"], "private key")) + "\n"
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("ascii"))
        private_key = serialization.load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        certificate_public = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        private_public = private_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(certificate_public, private_public)
        self.assertEqual(base64.b64encode(hashlib.sha256(certificate_public).digest()).decode("ascii"), identity["INTERSERVER_HY2_PUBLIC_KEY_SHA256"])
        validate_transport_identity(identity)

    def test_identity_validation_rejects_a_mismatched_pin(self) -> None:
        identity = generate_transport_identity()
        identity["INTERSERVER_HY2_PUBLIC_KEY_SHA256"] = base64.b64encode(bytes(32)).decode("ascii")
        with self.assertRaisesRegex(ValueError, "pin does not match"):
            validate_transport_identity(identity)

    def test_transport_password_is_stable_and_not_the_wireguard_key(self) -> None:
        preshared_key = base64.b64encode(bytes(range(32))).decode("ascii")
        first = derive_transport_password(preshared_key)
        self.assertEqual(first, derive_transport_password(preshared_key))
        self.assertNotEqual(first, preshared_key)
        self.assertNotIn("=", first)

    def test_transport_password_rejects_invalid_root_key(self) -> None:
        with self.assertRaisesRegex(ValueError, "preshared key"):
            derive_transport_password("not-base64")


if __name__ == "__main__":
    unittest.main()
