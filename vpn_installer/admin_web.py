from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import ipaddress
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    from . import admin_apply
except ImportError:  # pragma: no cover - standalone server-side execution
    import admin_apply  # type: ignore[no-redef]

ENV_PATH = Path("/etc/vpn-stack/deployment.env")
AUTH_PATH = Path("/etc/vpn-stack/admin-auth.json")
RULES_PATH = admin_apply.RULES_PATH
APPLY_SCRIPT = Path("/usr/local/lib/vpn-stack/admin_apply.py")
PBKDF2_ROUNDS = 200_000
CSRF_TOKEN = secrets.token_urlsafe(32)
CLIENT_IP_CACHE: dict[str, Any] = {"expires_at": 0.0, "listen_port": None, "ips": set()}


def load_env(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        env[key.strip()] = value
    return env


def hash_password(password: str, *, salt: str | None = None) -> dict[str, str | int]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return {"algorithm": "pbkdf2_sha256", "rounds": PBKDF2_ROUNDS, "salt": salt, "hash": digest.hex()}


def verify_password(password: str, payload: dict[str, Any]) -> bool:
    try:
        salt = str(payload["salt"])
        rounds = int(payload.get("rounds", PBKDF2_ROUNDS))
        expected = str(payload["hash"])
    except (KeyError, TypeError, ValueError):
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), rounds)
    return hmac.compare_digest(digest.hex(), expected)


def write_json_atomic(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def init_auth(username: str, password: str, *, force: bool = False) -> None:
    if AUTH_PATH.exists() and not force:
        return
    payload = {"username": username, "password": hash_password(password), "updated_at": int(time.time())}
    write_json_atomic(AUTH_PATH, payload)


def load_auth() -> dict[str, Any]:
    env = load_env()
    if not AUTH_PATH.exists():
        init_auth(env.get("ADMIN_WEB_USERNAME", "user") or "user", env.get("ADMIN_WEB_PASSWORD", "password") or "password")
    return json.loads(AUTH_PATH.read_text(encoding="utf-8"))


def check_basic_auth(header: str | None) -> bool:
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
    except Exception:
        return False
    auth = load_auth()
    return hmac.compare_digest(username, str(auth.get("username", ""))) and verify_password(password, auth.get("password", {}))


def is_loopback_bind(bind: str) -> bool:
    if bind in {"localhost"}:
        return True
    try:
        return ipaddress.ip_address(bind).is_loopback
    except ValueError:
        return False


def assert_safe_bind(env: dict[str, str]) -> None:
    bind = env.get("ADMIN_WEB_BIND", "127.0.0.1") or "127.0.0.1"
    if is_loopback_bind(bind):
        return
    username = env.get("ADMIN_WEB_USERNAME", "user") or "user"
    password = env.get("ADMIN_WEB_PASSWORD", "password") or "password"
    default_credentials = username == "user" and password == "password"
    if AUTH_PATH.exists():
        auth = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
        default_credentials = hmac.compare_digest(str(auth.get("username", "")), "user") and verify_password("password", auth.get("password", {}))
    client_match_enabled = env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() in {"1", "true", "yes", "on"}
    allow_wg = env.get("ADMIN_WEB_ALLOW_WG", "0").strip().lower() in {"1", "true", "yes", "on"}
    allowed_cidr = env.get("ADMIN_WEB_ALLOWED_CIDR", "").strip()
    if default_credentials and not (client_match_enabled and not allow_wg and not allowed_cidr):
        raise RuntimeError("ADMIN_WEB_BIND is public but admin credentials are still user/password")


def split_endpoint(endpoint: str) -> tuple[str, str]:
    value = endpoint.strip()
    if value.startswith("[") and "]:" in value:
        host, port = value[1:].split("]:", 1)
        return host, port
    host, sep, port = value.rpartition(":")
    if not sep:
        return "", ""
    return host, port


def parse_established_client_ips(ss_text: str, listen_port: int) -> set[str]:
    ips: set[str] = set()
    expected_port = str(listen_port)
    for line in ss_text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local_host, local_port = split_endpoint(parts[-2])
        peer_host, _peer_port = split_endpoint(parts[-1])
        if local_port != expected_port:
            continue
        try:
            ip = ipaddress.ip_address(peer_host.strip("[]"))
        except ValueError:
            continue
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.version == 4:
            ips.add(str(ip))
    return ips


def active_xray_client_ips(listen_port: int) -> set[str]:
    now = time.monotonic()
    if CLIENT_IP_CACHE["listen_port"] == listen_port and now < float(CLIENT_IP_CACHE["expires_at"]):
        return set(CLIENT_IP_CACHE["ips"])
    try:
        completed = subprocess.run(
            ["ss", "-Htn", "state", "established"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except Exception:
        ips: set[str] = set()
    else:
        ips = parse_established_client_ips(completed.stdout, listen_port)
    CLIENT_IP_CACHE.update({"expires_at": now + 1, "listen_port": listen_port, "ips": set(ips)})
    return ips


def active_client_ip_allowed(client_ip: str, env: dict[str, str]) -> bool:
    if env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    try:
        listen_port = int(env.get("RU_LISTEN_PORT", "443") or "443")
    except ValueError:
        listen_port = 443
    return client_ip in active_xray_client_ips(listen_port)


def any_active_client(env: dict[str, str]) -> bool:
    if env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return True
    try:
        listen_port = int(env.get("RU_LISTEN_PORT", "443") or "443")
    except ValueError:
        listen_port = 443
    return bool(active_xray_client_ips(listen_port))


def tunnel_source_allowed(client_ip: str, env: dict[str, str]) -> bool:
    if env.get("ADMIN_WEB_ALLOW_TUNNEL_CLIENTS", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    candidates = [
        env.get("RU_PUBLIC_IP", ""),
        env.get("FOREIGN_PUBLIC_IP", ""),
        env.get("WG_RU_ADDRESS", ""),
        env.get("WG_FOREIGN_ADDRESS", ""),
    ]
    for value in candidates:
        value = value.strip()
        if not value:
            continue
        try:
            if ip in ipaddress.ip_network(value, strict=False):
                return any_active_client(env)
        except ValueError:
            continue
    return False


def sync_admin_client_nft_set(env: dict[str, str]) -> None:
    if env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() not in {"1", "true", "yes", "on"}:
        return
    try:
        listen_port = int(env.get("RU_LISTEN_PORT", "443") or "443")
        timeout_seconds = int(env.get("ADMIN_WEB_ACTIVE_CLIENT_TIMEOUT_SECONDS", "5") or "5")
    except ValueError:
        listen_port = 443
        timeout_seconds = 5
    timeout_seconds = max(2, min(timeout_seconds, 300))
    for ip in active_xray_client_ips(listen_port):
        subprocess.run(
            ["nft", "add", "element", "inet", "vpnstack", "admin_clients_ipv4", f"{{ {ip} timeout {timeout_seconds}s }}"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )


def sync_admin_client_nft_set_loop() -> None:
    while True:
        try:
            sync_admin_client_nft_set(load_env())
        except Exception:
            pass
        time.sleep(1)


def client_ip_allowed(client_ip: str, env: dict[str, str]) -> bool:
    if is_loopback_bind(env.get("ADMIN_WEB_BIND", "127.0.0.1") or "127.0.0.1"):
        return True
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    if active_client_ip_allowed(str(ip), env):
        return True
    if tunnel_source_allowed(str(ip), env):
        return True
    allow_wg = env.get("ADMIN_WEB_ALLOW_WG", "0").strip().lower() in {"1", "true", "yes", "on"}
    if allow_wg:
        for key in ("WG_RU_ADDRESS", "WG_FOREIGN_ADDRESS"):
            value = env.get(key, "").strip()
            if not value:
                continue
            try:
                if ip in ipaddress.ip_network(value, strict=False):
                    return True
            except ValueError:
                continue
    cidrs = [item.strip() for item in env.get("ADMIN_WEB_ALLOWED_CIDR", "").replace(",", " ").split() if item.strip()]
    if not cidrs:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def load_rules() -> list[dict[str, Any]]:
    try:
        return admin_apply.load_rules(RULES_PATH)
    except Exception:
        return []


def save_rules(rules: list[dict[str, Any]]) -> None:
    write_json_atomic(RULES_PATH, {"rules": rules, "updated_at": int(time.time())})


def apply_rules() -> tuple[bool, str]:
    try:
        if APPLY_SCRIPT.exists():
            subprocess.run([sys.executable, str(APPLY_SCRIPT), "--no-restart"], check=True, capture_output=True, text=True, timeout=30)
        else:
            admin_apply.apply_rules(restart=False)
        return True, "Правила проверены и записаны."
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        return False, detail
    except Exception as exc:
        return False, str(exc)


def schedule_singbox_restart(delay_seconds: float = 0.35) -> None:
    def restart() -> None:
        time.sleep(delay_seconds)
        try:
            subprocess.run(["systemctl", "restart", "sing-box"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except Exception:
            pass

    threading.Thread(target=restart, daemon=True).start()


def commit_rules(new_rules: list[dict[str, Any]], old_rules: list[dict[str, Any]]) -> tuple[bool, str]:
    save_rules(new_rules)
    ok, message = apply_rules()
    if not ok:
        save_rules(old_rules)
        return False, message
    return True, message


def page(title: str, active: str, body: str, message: str = "") -> bytes:
    nav_routes = "active" if active == "routes" else ""
    nav_settings = "active" if active == "settings" else ""
    alert = f'<div class="alert alert-info">{html_escape(message)}</div>' if message else ""
    html = f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_escape(title)}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {{ background: linear-gradient(135deg, #f7f3e8 0%, #dce9ef 100%); min-height: 100vh; }}
    .shell {{ max-width: 1100px; }}
    .card {{ border: 0; box-shadow: 0 18px 45px rgba(38, 49, 55, .12); }}
    .navbar {{ backdrop-filter: blur(12px); }}
    .badge-server {{ min-width: 150px; }}
    code {{ color: #1f4f5f; }}
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg bg-white bg-opacity-75 border-bottom sticky-top">
  <div class="container shell">
    <a class="navbar-brand fw-bold" href="/routes">VPN Admin</a>
    <div class="navbar-nav">
      <a class="nav-link {nav_routes}" href="/routes">Исключения</a>
      <a class="nav-link {nav_settings}" href="/settings">Доступ</a>
    </div>
  </div>
</nav>
<main class="container shell py-4">
  {alert}
  {body}
</main>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script>window.CSRF_TOKEN = "{CSRF_TOKEN}";</script>
{ROUTES_SCRIPT if active == "routes" else ""}
</body>
</html>"""
    return html.encode("utf-8")


def html_escape(value: Any) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


ROUTES_BODY = """
<div class="row g-4">
  <div class="col-lg-5">
    <div class="card">
      <div class="card-body p-4">
        <h1 class="h4 mb-3">Новое исключение</h1>
        <p class="text-muted">Правило применяется на российском router сразу после сохранения.</p>
        <div class="mb-3">
          <label class="form-label">Домен или CIDR</label>
          <input id="rule-value" class="form-control form-control-lg" placeholder="example.com или *.example.com">
          <div class="form-text">CIDR тоже поддерживается: <code>203.0.113.0/24</code>.</div>
        </div>
        <div class="form-check form-switch mb-3">
          <input id="rule-subdomains" class="form-check-input" type="checkbox">
          <label class="form-check-label" for="rule-subdomains">Включить все поддомены</label>
        </div>
        <div class="mb-3">
          <label class="form-label">Через какой сервер открывать</label>
          <select id="rule-outbound" class="form-select">
            <option value="direct-ru">российский сервер</option>
            <option value="to-foreign">зарубежный сервер</option>
          </select>
        </div>
        <div class="alert alert-warning small">
          Если российский IP отправить на зарубежный сервер, его может отрезать foreign-side RU block. Это будет видно в диагностике.
        </div>
        <button id="add-rule" class="btn btn-dark btn-lg w-100">Добавить и применить</button>
      </div>
    </div>
  </div>
  <div class="col-lg-7">
    <div class="card">
      <div class="card-body p-4">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h2 class="h4 mb-0">Текущие исключения</h2>
          <button id="refresh-rules" class="btn btn-outline-secondary btn-sm">Обновить</button>
        </div>
        <div id="rules-message"></div>
        <div class="table-responsive">
          <table class="table align-middle">
            <thead>
              <tr>
                <th>Значение</th>
                <th>Сервер</th>
                <th>Поддомены</th>
                <th></th>
              </tr>
            </thead>
            <tbody id="rules-table"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
</div>
"""


ROUTES_SCRIPT = """
<script>
function serverLabel(outbound) {
  return outbound === "to-foreign" ? "зарубежный сервер" : "российский сервер";
}
function showMessage(kind, text) {
  $("#rules-message").html('<div class="alert alert-' + kind + '">' + $("<div>").text(text).html() + '</div>');
}
function renderRules(rules) {
  const body = $("#rules-table").empty();
  if (!rules.length) {
    body.append('<tr><td colspan="4" class="text-muted">Исключений пока нет.</td></tr>');
    return;
  }
  rules.forEach(function(rule) {
    const value = $("<span>").text(rule.value).html();
    const row = $('<tr>').attr("data-id", rule.id);
    row.append('<td><div class="d-flex align-items-center gap-2"><div class="form-check form-switch mb-0"><input class="form-check-input rule-enabled" type="checkbox" ' + (rule.enabled ? "checked" : "") + '></div><code>' + value + '</code></div></td>');
    row.append('<td><select class="form-select form-select-sm rule-outbound"><option value="direct-ru">российский сервер</option><option value="to-foreign">зарубежный сервер</option></select></td>');
    row.append('<td><div class="form-check form-switch mb-0"><input class="form-check-input rule-subdomains" type="checkbox" ' + (rule.include_subdomains ? "checked" : "") + '></div></td>');
    row.append('<td class="text-end"><button class="btn btn-outline-danger btn-sm rule-delete">Удалить</button></td>');
    row.find(".rule-outbound").val(rule.outbound);
    body.append(row);
  });
}
function setFormBusy(busy) {
  $("#rule-value, #rule-subdomains, #rule-outbound, #add-rule, #refresh-rules").prop("disabled", busy);
}
function setRowBusy(row, busy) {
  row.find("input, select, button").prop("disabled", busy);
  row.toggleClass("opacity-50", busy);
}
function loadRules() {
  $.getJSON("/api/routes", function(data) {
    renderRules(data.rules || []);
  });
}
$("#add-rule").on("click", function() {
  const payload = {
    value: $("#rule-value").val(),
    include_subdomains: $("#rule-subdomains").is(":checked"),
    outbound: $("#rule-outbound").val()
  };
  $.ajax({
    url: "/api/routes",
    method: "POST",
    contentType: "application/json",
    headers: {"X-CSRF-Token": window.CSRF_TOKEN},
    data: JSON.stringify(payload),
    beforeSend: function() {
      setFormBusy(true);
    },
    success: function(data) {
      showMessage("success", data.message || "Сохранено.");
      renderRules(data.rules || []);
      $("#rule-value").val("");
      $("#rule-subdomains").prop("checked", false);
    },
    error: function(xhr) {
      const data = xhr.responseJSON || {};
      showMessage("danger", data.error || (xhr.status === 0 ? "Соединение оборвалось во время применения. Обнови список." : "Ошибка сохранения."));
    },
    complete: function() {
      setFormBusy(false);
    }
  });
});
$("#rules-table").on("click", ".rule-delete", function() {
  const row = $(this).closest("tr");
  $.ajax({
    url: "/api/routes/" + encodeURIComponent(row.data("id")),
    method: "DELETE",
    headers: {"X-CSRF-Token": window.CSRF_TOKEN},
    beforeSend: function() {
      setRowBusy(row, true);
    },
    success: function(data) {
      showMessage("success", data.message || "Удалено.");
      renderRules(data.rules || []);
    },
    error: function(xhr) {
      const data = xhr.responseJSON || {};
      showMessage("danger", data.error || "Ошибка удаления.");
      setRowBusy(row, false);
    }
  });
});
$("#rules-table").on("change", ".rule-enabled, .rule-subdomains, .rule-outbound", function() {
  const row = $(this).closest("tr");
  const payload = {
    enabled: row.find(".rule-enabled").is(":checked"),
    include_subdomains: row.find(".rule-subdomains").is(":checked"),
    outbound: row.find(".rule-outbound").val()
  };
  $.ajax({
    url: "/api/routes/" + encodeURIComponent(row.data("id")),
    method: "PATCH",
    contentType: "application/json",
    headers: {"X-CSRF-Token": window.CSRF_TOKEN},
    data: JSON.stringify(payload),
    beforeSend: function() {
      setRowBusy(row, true);
    },
    success: function(data) {
      showMessage("success", data.message || "Правило обновлено.");
      renderRules(data.rules || []);
    },
    error: function(xhr) {
      const data = xhr.responseJSON || {};
      showMessage("danger", data.error || "Ошибка обновления.");
      loadRules();
    }
  });
});
$("#refresh-rules").on("click", loadRules);
$(loadRules);
</script>
"""


def settings_body(message: str = "") -> bytes:
    auth = load_auth()
    username = html_escape(auth.get("username", "user"))
    body = f"""
<div class="card">
  <div class="card-body p-4">
    <h1 class="h4 mb-3">Настройка доступа</h1>
    <p class="text-muted">После смены логина или пароля браузер может запросить авторизацию заново.</p>
    <form method="post" action="/settings" class="row g-3">
      <input type="hidden" name="csrf" value="{CSRF_TOKEN}">
      <div class="col-md-6">
        <label class="form-label">Логин</label>
        <input name="username" class="form-control" value="{username}" required>
      </div>
      <div class="col-md-6">
        <label class="form-label">Текущий пароль</label>
        <input name="current_password" type="password" class="form-control" required>
      </div>
      <div class="col-md-6">
        <label class="form-label">Новый пароль</label>
        <input name="new_password" type="password" class="form-control" minlength="8" required>
      </div>
      <div class="col-md-6">
        <label class="form-label">Повтор нового пароля</label>
        <input name="confirm_password" type="password" class="form-control" minlength="8" required>
      </div>
      <div class="col-12">
        <button class="btn btn-dark">Сохранить доступ</button>
      </div>
    </form>
  </div>
</div>
"""
    return page("VPN Admin: доступ", "settings", body, message)


class Handler(BaseHTTPRequestHandler):
    server_version = "VPNAdmin/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def drop_connection(self) -> None:
        self.close_connection = True
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.connection.close()
        except OSError:
            pass

    def require_auth(self) -> bool:
        env = load_env()
        if not client_ip_allowed(self.client_address[0], env):
            self.drop_connection()
            return False
        if check_basic_auth(self.headers.get("Authorization")):
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="VPN Admin", charset="UTF-8"')
        self.end_headers()
        self.wfile.write("Authentication required\n".encode("utf-8"))
        return False

    def require_csrf(self) -> bool:
        token = self.headers.get("X-CSRF-Token", "")
        if token != CSRF_TOKEN:
            self.send_json({"error": "CSRF token mismatch"}, HTTPStatus.FORBIDDEN)
            return False
        return True

    def send_html(self, payload: bytes, status: int = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Set-Cookie", f"csrf={CSRF_TOKEN}; SameSite=Strict")
        self.end_headers()
        self.wfile.write(payload)

    def send_json(self, payload: Any, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        try:
            self.wfile.flush()
        except OSError:
            pass

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self) -> None:
        if not self.require_auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path in {"", "/"}:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", "/routes")
            self.end_headers()
        elif path == "/routes":
            self.send_html(page("VPN Admin: исключения", "routes", ROUTES_BODY))
        elif path == "/settings":
            self.send_html(settings_body())
        elif path == "/api/routes":
            self.send_json({"rules": load_rules()})
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self.require_auth():
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/routes":
            if not self.require_csrf():
                return
            try:
                raw_rule = self.read_json()
                raw_rule["id"] = secrets.token_hex(8)
                rule = admin_apply.normalize_rule(raw_rule)
                old_rules = load_rules()
                new_rules = [*old_rules, rule]
                ok, message = commit_rules(new_rules, old_rules)
                if not ok:
                    raise RuntimeError(message)
                self.send_json({"rules": load_rules(), "message": "Правило сохранено и применено."})
                schedule_singbox_restart()
            except Exception as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        elif path == "/settings":
            length = int(self.headers.get("Content-Length", "0") or "0")
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8"))
            if form.get("csrf", [""])[0] != CSRF_TOKEN:
                self.send_html(settings_body("CSRF token mismatch."), HTTPStatus.FORBIDDEN)
                return
            username = form.get("username", [""])[0].strip()
            current = form.get("current_password", [""])[0]
            new = form.get("new_password", [""])[0]
            confirm = form.get("confirm_password", [""])[0]
            auth = load_auth()
            if not username:
                self.send_html(settings_body("Логин не может быть пустым."), HTTPStatus.BAD_REQUEST)
            elif not verify_password(current, auth.get("password", {})):
                self.send_html(settings_body("Текущий пароль неверный."), HTTPStatus.BAD_REQUEST)
            elif len(new) < 8:
                self.send_html(settings_body("Новый пароль должен быть не короче 8 символов."), HTTPStatus.BAD_REQUEST)
            elif new != confirm:
                self.send_html(settings_body("Новые пароли не совпадают."), HTTPStatus.BAD_REQUEST)
            else:
                init_auth(username, new, force=True)
                self.send_html(settings_body("Доступ обновлён. Если браузер держит старый Basic Auth, открой страницу заново."), HTTPStatus.OK)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        if not self.require_auth():
            return
        if not self.require_csrf():
            return
        path = urllib.parse.urlparse(self.path).path
        prefix = "/api/routes/"
        if not path.startswith(prefix):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        rule_id = urllib.parse.unquote(path[len(prefix):])
        old_rules = load_rules()
        matched = False
        try:
            patch = self.read_json()
            new_rules: list[dict[str, Any]] = []
            for rule in old_rules:
                if rule.get("id") != rule_id:
                    new_rules.append(rule)
                    continue
                matched = True
                merged = {**rule}
                for key in ("enabled", "include_subdomains", "outbound"):
                    if key in patch:
                        merged[key] = patch[key]
                new_rules.append(admin_apply.normalize_rule(merged))
            if not matched:
                self.send_json({"error": "Правило не найдено."}, HTTPStatus.NOT_FOUND)
                return
            ok, message = commit_rules(new_rules, old_rules)
            if not ok:
                raise RuntimeError(message)
            self.send_json({"rules": load_rules(), "message": "Правило обновлено и применено."})
            schedule_singbox_restart()
        except Exception as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self) -> None:
        if not self.require_auth():
            return
        if not self.require_csrf():
            return
        path = urllib.parse.urlparse(self.path).path
        prefix = "/api/routes/"
        if not path.startswith(prefix):
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        rule_id = urllib.parse.unquote(path[len(prefix):])
        old_rules = load_rules()
        new_rules = [rule for rule in old_rules if rule.get("id") != rule_id]
        if len(new_rules) == len(old_rules):
            self.send_json({"error": "Правило не найдено."}, HTTPStatus.NOT_FOUND)
            return
        ok, message = commit_rules(new_rules, old_rules)
        if not ok:
            self.send_json({"error": message}, HTTPStatus.BAD_REQUEST)
            return
        self.send_json({"rules": load_rules(), "message": "Правило удалено и конфиг применён."})
        schedule_singbox_restart()


class StealthAdminServer(ThreadingHTTPServer):
    def verify_request(self, request: Any, client_address: tuple[Any, ...]) -> bool:
        env = load_env()
        client_ip = str(client_address[0]) if client_address else ""
        allowed = client_ip_allowed(client_ip, env)
        if not allowed:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass
        return allowed


def serve() -> None:
    env = load_env()
    bind = env.get("ADMIN_WEB_BIND", "127.0.0.1") or "127.0.0.1"
    port = int(env.get("ADMIN_WEB_PORT", "11333") or "11333")
    assert_safe_bind(env)
    init_auth(env.get("ADMIN_WEB_USERNAME", "user") or "user", env.get("ADMIN_WEB_PASSWORD", "password") or "password")
    if env.get("ADMIN_WEB_ACTIVE_CLIENT_REQUIRED", "1").strip().lower() in {"1", "true", "yes", "on"}:
        sync_admin_client_nft_set(env)
        threading.Thread(target=sync_admin_client_nft_set_loop, daemon=True).start()
    StealthAdminServer((bind, port), Handler).serve_forever()


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if argv and argv[0] == "init-auth":
        username = argv[1] if len(argv) > 1 else "user"
        password = argv[2] if len(argv) > 2 else "password"
        force = "--force" in argv
        init_auth(username, password, force=force)
        return 0
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
