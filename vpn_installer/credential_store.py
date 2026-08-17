from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Protocol

from .common import command_exists, run_command
from .models import AppError


class CredentialStoreError(AppError):
    pass


@dataclass(frozen=True)
class SSHCredentialRef:
    host: str
    port: int
    user: str

    @property
    def windows_target(self) -> str:
        return f"vpn-installer:ssh:{self.user}@{self.host}:{self.port}"

    @property
    def secret_tool_attributes(self) -> tuple[str, ...]:
        return (
            "application",
            "vpn-installer",
            "protocol",
            "ssh",
            "host",
            self.host,
            "port",
            str(self.port),
            "user",
            self.user,
        )


class CredentialStore(Protocol):
    label: str

    def load(self, credential: SSHCredentialRef) -> str | None: ...

    def save(self, credential: SSHCredentialRef, password: str) -> None: ...

    def delete(self, credential: SSHCredentialRef) -> None: ...


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


class WindowsCredentialStore:
    label = "Windows Credential Manager"
    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2
    _ERROR_NOT_FOUND = 1168
    _MAX_BLOB_BYTES = 5 * 512

    def __init__(self, api: Any | None = None) -> None:
        self._api = api or self._load_api()

    @staticmethod
    def _load_api() -> Any:
        if os.name != "nt":
            raise CredentialStoreError("Windows Credential Manager недоступен на этой платформе.")
        api = ctypes.WinDLL("Advapi32.dll", use_last_error=True)  # type: ignore[attr-defined]
        api.CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
        api.CredWriteW.restype = wintypes.BOOL
        api.CredReadW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)),
        ]
        api.CredReadW.restype = wintypes.BOOL
        api.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        api.CredDeleteW.restype = wintypes.BOOL
        api.CredFree.argtypes = [ctypes.c_void_p]
        api.CredFree.restype = None
        return api

    @staticmethod
    def _last_error() -> int:
        return int(ctypes.get_last_error())

    def load(self, credential: SSHCredentialRef) -> str | None:
        result = ctypes.POINTER(_CREDENTIALW)()
        if not self._api.CredReadW(
            credential.windows_target,
            self._CRED_TYPE_GENERIC,
            0,
            ctypes.byref(result),
        ):
            error = self._last_error()
            if error == self._ERROR_NOT_FOUND:
                return None
            raise CredentialStoreError(f"Не удалось прочитать сохранённый SSH-пароль (Windows error {error}).")
        try:
            record = result.contents
            if not record.CredentialBlob or record.CredentialBlobSize == 0:
                return None
            raw = ctypes.string_at(record.CredentialBlob, record.CredentialBlobSize)
            return raw.decode("utf-16-le")
        except (UnicodeDecodeError, ValueError) as exc:
            raise CredentialStoreError("Сохранённый SSH-пароль повреждён.") from exc
        finally:
            self._api.CredFree(result)

    def save(self, credential: SSHCredentialRef, password: str) -> None:
        if not password:
            raise CredentialStoreError("Пустой SSH-пароль сохранять нельзя.")
        encoded = password.encode("utf-16-le")
        if len(encoded) > self._MAX_BLOB_BYTES:
            raise CredentialStoreError("SSH-пароль слишком длинный для Windows Credential Manager.")
        blob = ctypes.create_string_buffer(encoded)
        record = _CREDENTIALW(
            Flags=0,
            Type=self._CRED_TYPE_GENERIC,
            TargetName=credential.windows_target,
            Comment="VPN Installer SSH password",
            CredentialBlobSize=len(encoded),
            CredentialBlob=ctypes.cast(blob, ctypes.POINTER(ctypes.c_ubyte)),
            Persist=self._CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount=0,
            Attributes=None,
            TargetAlias=None,
            UserName=credential.user,
        )
        if not self._api.CredWriteW(ctypes.byref(record), 0):
            error = self._last_error()
            raise CredentialStoreError(f"Не удалось сохранить SSH-пароль (Windows error {error}).")

    def delete(self, credential: SSHCredentialRef) -> None:
        if self._api.CredDeleteW(credential.windows_target, self._CRED_TYPE_GENERIC, 0):
            return
        error = self._last_error()
        if error != self._ERROR_NOT_FOUND:
            raise CredentialStoreError(f"Не удалось удалить сохранённый SSH-пароль (Windows error {error}).")


class SecretToolCredentialStore:
    label = "Secret Service"

    @staticmethod
    def _run(args: list[str], *, password: str | None = None):
        return run_command(
            ["secret-tool", *args],
            capture_output=True,
            check=False,
            input_text=(password + "\n") if password is not None else None,
            timeout=15,
        )

    def load(self, credential: SSHCredentialRef) -> str | None:
        completed = self._run(["lookup", *credential.secret_tool_attributes])
        if completed.returncode == 0:
            return (completed.stdout or "").rstrip("\r\n") or None
        detail = (completed.stderr or "").strip()
        if detail:
            raise CredentialStoreError(f"Secret Service недоступен: {detail}")
        return None

    def save(self, credential: SSHCredentialRef, password: str) -> None:
        if not password:
            raise CredentialStoreError("Пустой SSH-пароль сохранять нельзя.")
        completed = self._run(
            ["store", "--label=VPN Installer SSH password", *credential.secret_tool_attributes],
            password=password,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or "").strip() or f"exit code {completed.returncode}"
            raise CredentialStoreError(f"Не удалось сохранить SSH-пароль в Secret Service: {detail}")

    def delete(self, credential: SSHCredentialRef) -> None:
        completed = self._run(["clear", *credential.secret_tool_attributes])
        if completed.returncode not in {0, 1}:
            detail = (completed.stderr or "").strip() or f"exit code {completed.returncode}"
            raise CredentialStoreError(f"Не удалось удалить SSH-пароль из Secret Service: {detail}")


def system_credential_store(*, platform_name: str | None = None) -> CredentialStore | None:
    platform = platform_name or os.name
    if platform == "nt":
        return WindowsCredentialStore()
    if platform == "posix" and command_exists("secret-tool"):
        return SecretToolCredentialStore()
    return None
