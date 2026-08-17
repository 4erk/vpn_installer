from __future__ import annotations

import ctypes
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from vpn_installer.credential_store import (
    SSHCredentialRef,
    SecretToolCredentialStore,
    WindowsCredentialStore,
    _CREDENTIALW,
    system_credential_store,
)


class CredentialStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.credential = SSHCredentialRef("ssh.example.test", 2222, "root")

    def test_reference_is_stable_and_contains_no_password(self) -> None:
        self.assertEqual(
            self.credential.windows_target,
            "vpn-installer:ssh:root@ssh.example.test:2222",
        )
        self.assertEqual(
            self.credential.secret_tool_attributes,
            (
                "application",
                "vpn-installer",
                "protocol",
                "ssh",
                "host",
                "ssh.example.test",
                "port",
                "2222",
                "user",
                "root",
            ),
        )

    def test_windows_store_writes_utf16_secret_outside_command_line(self) -> None:
        api = SimpleNamespace(CredWriteW=Mock(return_value=True))
        store = WindowsCredentialStore(api=api)
        store.save(self.credential, "секрет")
        record = api.CredWriteW.call_args.args[0]._obj
        self.assertEqual(record.TargetName, self.credential.windows_target)
        self.assertEqual(record.UserName, "root")
        self.assertEqual(
            ctypes.string_at(record.CredentialBlob, record.CredentialBlobSize).decode("utf-16-le"),
            "секрет",
        )

    def test_windows_store_reads_and_frees_secret(self) -> None:
        encoded = "secret".encode("utf-16-le")
        blob = ctypes.create_string_buffer(encoded)
        record = _CREDENTIALW(
            CredentialBlobSize=len(encoded),
            CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)),
        )
        pointer = ctypes.pointer(record)

        def read(_target, _kind, _flags, output) -> bool:
            ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)))[0] = pointer
            return True

        api = SimpleNamespace(CredReadW=Mock(side_effect=read), CredFree=Mock())
        store = WindowsCredentialStore(api=api)
        self.assertEqual(store.load(self.credential), "secret")
        api.CredFree.assert_called_once()

    def test_secret_tool_passes_password_via_stdin(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch("vpn_installer.credential_store.run_command", return_value=completed) as run:
            SecretToolCredentialStore().save(self.credential, "secret")
        args = run.call_args.args[0]
        self.assertNotIn("secret", args)
        self.assertEqual(run.call_args.kwargs["input_text"], "secret\n")

    def test_backend_selection_has_no_plaintext_fallback(self) -> None:
        with patch("vpn_installer.credential_store.command_exists", return_value=False):
            self.assertIsNone(system_credential_store(platform_name="posix"))


if __name__ == "__main__":
    unittest.main()
