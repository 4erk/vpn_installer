from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

try:
    from . import admin_apply
except ImportError:  # pragma: no cover - standalone server-side execution
    import admin_apply  # type: ignore[no-redef]

ENV_PATH = Path("/etc/vpn-stack/deployment.env")
AUTH_PATH = Path("/etc/vpn-stack/admin-auth.json")
RULES_PATH = admin_apply.RULES_PATH
PBKDF2_ROUNDS = 200_000
CSRF_TOKEN = secrets.token_urlsafe(32)
ADMIN_BIND = "0.0.0.0"


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


def load_rules() -> list[dict[str, Any]]:
    return admin_apply.load_rules(RULES_PATH)


def commit_rules(new_rules: list[dict[str, Any]], old_rules: list[dict[str, Any]]) -> tuple[bool, str]:
    try:
        admin_apply.commit_rules(
            new_rules,
            rules_path=RULES_PATH,
            restart=True,
            expected_generation=admin_apply.rules_generation(old_rules),
        )
        return True, "Правила проверены, применены и сервис подтверждён."
    except admin_apply.RulesConflictError:
        raise
    except Exception as exc:
        return False, str(exc)


def routes_payload() -> dict[str, Any]:
    env = load_env()
    rules = load_rules()
    base_config = admin_apply.read_json(admin_apply.BASE_CONFIG_PATH, {})
    catalog = admin_apply.outbound_catalog(base_config) if isinstance(base_config, dict) else {}
    return {
        "rules": rules,
        "generation": admin_apply.rules_generation(rules),
        "config": {
            "topology": env.get("TOPOLOGY", ""),
            "gateway_location": env.get("GATEWAY_LOCATION", ""),
            "foreign_block_ru": env.get("FOREIGN_BLOCK_RU", "0").strip() == "1",
            "egresses": list(catalog.values()),
        },
    }


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
    <div class="navbar-nav flex-row flex-nowrap gap-3 align-items-center">
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
        <p class="text-muted">Правило применяется на gateway сразу после сохранения.</p>
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
          <select id="rule-outbound" class="form-select"></select>
        </div>
        <div id="foreign-block-warning" class="alert alert-warning small d-none">
          Foreign-side RU block включён. Российские IP через зарубежный сервер могут отрезаться на foreign host.
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
let routeEgresses = [];
function serverLabel(outbound) {
  const item = routeEgresses.find(function(entry) { return entry.tag === outbound; });
  return item ? item.label : outbound;
}
function egressOptions(selected) {
  const options = routeEgresses.map(function(entry) {
    return '<option value="' + $("<div>").text(entry.tag).html() + '">' + $("<div>").text(entry.label).html() + '</option>';
  }).join("");
  if (selected && !routeEgresses.some(function(entry) { return entry.tag === selected; })) {
    return options + '<option value="' + $("<div>").text(selected).html() + '" disabled>' + $("<div>").text(selected + " (недоступно)").html() + '</option>';
  }
  return options;
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
    const conflict = rule.conflict ? '<div class="text-danger small mt-1">' + $("<div>").text(rule.conflict).html() + '</div>' : '';
    row.append('<td><select class="form-select form-select-sm rule-outbound">' + egressOptions(rule.outbound) + '</select>' + conflict + '</td>');
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
function setLoadingRules() {
  $("#rules-table").html('<tr><td colspan="4" class="text-muted"><span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>Загружаю исключения...</td></tr>');
}
function applyRoutesConfig(config) {
  routeEgresses = (config && config.egresses) || [];
  $("#rule-outbound").html(egressOptions());
  $("#foreign-block-warning").toggleClass("d-none", !(config && config.foreign_block_ru));
}
function loadRules() {
  setLoadingRules();
  $.getJSON("/api/routes", function(data) {
    applyRoutesConfig(data.config || {});
    renderRules(data.rules || []);
  }).fail(function(xhr) {
    const data = xhr.responseJSON || {};
    $("#rules-table").html('<tr><td colspan="4" class="text-danger">' + $("<div>").text(data.error || "Не удалось загрузить список исключений.").html() + '</td></tr>');
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
      applyRoutesConfig(data.config || {});
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
      applyRoutesConfig(data.config || {});
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
      applyRoutesConfig(data.config || {});
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

    def require_auth(self) -> bool:
        if check_basic_auth(self.headers.get("Authorization")):
            return True
        data = "Authentication required\n".encode("utf-8")
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="VPN Admin", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
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
        self.send_header("Content-Length", str(len(payload)))
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
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/routes":
            self.send_html(page("VPN Admin: исключения", "routes", ROUTES_BODY))
        elif path == "/settings":
            self.send_html(settings_body())
        elif path == "/api/routes":
            try:
                self.send_json(routes_payload())
            except Exception as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
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
                self.send_json({**routes_payload(), "message": "Правило сохранено и применено."})
            except admin_apply.RulesConflictError as exc:
                self.send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
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
        try:
            old_rules = load_rules()
            matched = False
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
            self.send_json({**routes_payload(), "message": "Правило обновлено и применено."})
        except admin_apply.RulesConflictError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
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
        try:
            old_rules = load_rules()
            new_rules = [rule for rule in old_rules if rule.get("id") != rule_id]
            if len(new_rules) == len(old_rules):
                self.send_json({"error": "Правило не найдено."}, HTTPStatus.NOT_FOUND)
                return
            ok, message = commit_rules(new_rules, old_rules)
            if not ok:
                self.send_json({"error": message}, HTTPStatus.BAD_REQUEST)
                return
            self.send_json({**routes_payload(), "message": "Правило удалено и конфиг применён."})
        except admin_apply.RulesConflictError as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        except Exception as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def serve() -> None:
    env = load_env()
    port = int(env.get("ADMIN_WEB_PORT", "11333") or "11333")
    init_auth(env.get("ADMIN_WEB_USERNAME", "user") or "user", env.get("ADMIN_WEB_PASSWORD", "password") or "password")
    ThreadingHTTPServer((ADMIN_BIND, port), Handler).serve_forever()


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
