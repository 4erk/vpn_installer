from __future__ import annotations

import os

from .common import command_exists, run_command


def copy_to_clipboard(payload: str) -> tuple[bool, str]:
    payload = payload.rstrip("\n")
    if os.name == "nt":
        if command_exists("powershell"):
            completed = run_command(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                ],
                input_text=payload,
                capture_output=True,
                check=False,
            )
            if completed.returncode == 0:
                return True, "URI скопирована в буфер обмена Windows."
            return False, (completed.stderr or completed.stdout or "Не удалось использовать Set-Clipboard.").strip()
        return False, "PowerShell не найден, буфер обмена недоступен."
    clipboard_tools = [
        (["wl-copy"], "URI скопирована через wl-copy."),
        (["xclip", "-selection", "clipboard"], "URI скопирована через xclip."),
        (["xsel", "--clipboard", "--input"], "URI скопирована через xsel."),
    ]
    for command, ok_message in clipboard_tools:
        if not command_exists(command[0]):
            continue
        completed = run_command(command, input_text=payload, capture_output=True, check=False)
        if completed.returncode == 0:
            return True, ok_message
    return False, "Буфер обмена недоступен, используй локальный файл с URI."
