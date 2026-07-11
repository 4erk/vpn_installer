from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteFailClass:
    name: str
    cache_prefix: str
    log_grep: str
    destination_sed: str
    exclude_grep: str = ""

    @property
    def count_key(self) -> str:
        return f"route_fail_{self.name}_count"

    @property
    def top_dest_key(self) -> str:
        return f"route_fail_{self.name}_top_dest"

    @property
    def age_key(self) -> str:
        return f"route_fail_{self.name}_age_s"


ROUTE_FAIL_CLASSES: tuple[RouteFailClass, ...] = (
    RouteFailClass(
        "domain_foreign",
        "DOMAIN_FOREIGN",
        r"outbound/direct\[to-foreign\].*i/o timeout",
        r"s/.*open connection to \([^ ]*\) using outbound\/direct\[to-foreign\].*/\1/p",
    ),
    RouteFailClass(
        "ipv4_literal",
        "IPV4_LITERAL",
        r"outbound/direct\[to-foreign-ip-literal\].*i/o timeout",
        r"s/.*open connection to \([^ ]*\) using outbound\/direct\[to-foreign-ip-literal\].*/\1/p",
        r"open connection to \[[0-9A-Fa-f:.]+\]",
    ),
    RouteFailClass(
        "ipv6_literal",
        "IPV6_LITERAL",
        r"outbound/direct\[to-foreign-ipv6-literal\]|open connection to \[[0-9A-Fa-f:.]+\].*outbound/direct\[to-foreign-ip-literal\]",
        r"s/.*open connection to \(\[[0-9A-Fa-f:.]*\]:[0-9][0-9]*\) using outbound\/direct\[[^]]*\].*/\1/p",
    ),
)


def _shell_single_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _route_fail_pipeline(route_class: RouteFailClass) -> str:
    pipeline = f'printf \'%s\\n\' "${{recent_log}}" | grep -E {_shell_single_quote(route_class.log_grep)}'
    if route_class.exclude_grep:
        pipeline += f" | grep -Ev {_shell_single_quote(route_class.exclude_grep)}"
    return pipeline


def render_route_fail_collector_shell() -> str:
    union_pattern = "|".join(route_class.log_grep for route_class in ROUTE_FAIL_CLASSES)
    declarations = " ".join(
        f'{route_class.name}_count="0" {route_class.name}_top=""'
        for route_class in ROUTE_FAIL_CLASSES
    )
    reset_lines = "\n".join(f'    reset_route_fail_bucket "{route_class.cache_prefix}"' for route_class in ROUTE_FAIL_CLASSES)
    count_lines = "\n".join(
        f'  {route_class.name}_count="$({_route_fail_pipeline(route_class)} | grep -c . || true)"'
        for route_class in ROUTE_FAIL_CLASSES
    )
    top_lines = "\n".join(
        f'  {route_class.name}_top="$({_route_fail_pipeline(route_class)} | sed -n {_shell_single_quote(route_class.destination_sed)} | sort | uniq -c | sort -nr | head -n1 | awk \'{{print $2 "=" $1}}\' || true)"'
        for route_class in ROUTE_FAIL_CLASSES
    )
    decision_blocks: list[str] = []
    for route_class in ROUTE_FAIL_CLASSES:
        adapt_line = ""
        if route_class.name == "ipv4_literal":
            adapt_line = f'    maybe_adapt_ipv4_literal_route "${{{route_class.name}_top}}"\n'
        elif route_class.name == "domain_foreign":
            adapt_line = f'    maybe_drop_adaptive_ipv4_route "${{{route_class.name}_top}}"\n'
        decision_blocks.append(
            f'  if [[ "${{{route_class.name}_count}}" =~ ^[0-9]+$ && "${{{route_class.name}_count}}" -ge "${{ROUTE_FAIL_THRESHOLD}}" ]]; then\n'
            f'    mark_route_fail_bucket "{route_class.cache_prefix}" "${{{route_class.name}_count}}" "${{{route_class.name}_top}}"\n'
            f"    printf '{route_class.name}_timeout_recent=%s:%s\\n' \"${{{route_class.name}_count}}\" \"${{{route_class.name}_top}}\"\n"
            f"{adapt_line}"
            f'  elif [[ "${{{route_class.name}_count}}" == "0" ]]; then\n'
            f'    reset_route_fail_bucket "{route_class.cache_prefix}"\n'
            "  fi"
        )
    decision_lines = "\n".join(decision_blocks)
    return "\n".join(
        [
            "route_fail_journal_since() {",
            '  local ttl="${ROUTE_FAIL_CACHE_TTL_SECONDS}"',
            '  local since="-${ttl} seconds"',
            '  local installed_at="" now_epoch="" installed_epoch="" ttl_epoch="" post_install_epoch=""',
            "  if [[ -r /etc/vpn-stack/installed_at ]] && command -v date >/dev/null 2>&1; then",
            "    installed_at=\"$(tr -d '\\r\\n' </etc/vpn-stack/installed_at)\"",
            '    now_epoch="$(date +%s 2>/dev/null || true)"',
            '    installed_epoch="$(date -d "${installed_at}" +%s 2>/dev/null || true)"',
            '    if [[ "${now_epoch}" =~ ^[0-9]+$ && "${installed_epoch}" =~ ^[0-9]+$ ]]; then',
            "      ttl_epoch=$((now_epoch - ttl))",
            "      post_install_epoch=$((installed_epoch + 10))",
            "      if (( post_install_epoch > ttl_epoch )); then",
            '        since="@${post_install_epoch}"',
            "      fi",
            "    fi",
            "  fi",
            '  printf "%s\\n" "${since}"',
            "}",
            "adaptive_ipv4_from_top_dest() {",
            '  local top_dest="$1"',
            '  local endpoint="${top_dest%%=*}"',
            '  local host="${endpoint%:*}"',
            '  local port="${endpoint##*:}"',
            '  if [[ "${host}" =~ ^([0-9]{1,3}\\.){3}[0-9]{1,3}$ && "${port}" =~ ^[0-9]+$ ]]; then',
            '    printf "%s %s\\n" "${host}" "${port}"',
            "  fi",
            "}",
            "adaptive_ipv4_literal_is_live() {",
            '  local host="$1"',
            '  local port="$2"',
            '  local scheme="http"',
            '  local rc="0" ok_count="0" attempt=""',
            '  command -v curl >/dev/null 2>&1 || return 1',
            '  if [[ "${port}" == "443" ]]; then scheme="https"; fi',
            '  for attempt in 1 2 3; do',
            '    rc="0"',
            '    curl -4ksS --interface "${WG_INTERFACE}" --connect-timeout 2 --max-time 3 -o /dev/null "${scheme}://${host}:${port}/" >/dev/null 2>&1 || rc="$?"',
            '    if [[ "${rc}" == "0" || "${rc}" == "35" || "${rc}" == "52" ]]; then',
            '      ok_count="$((ok_count + 1))"',
            "    fi",
            "  done",
            '  (( ok_count >= 2 ))',
            "}",
            "write_adaptive_ipv4_literal_rule() {",
            '  local host="$1"',
            '  local reason="$2"',
            "  if [[ -x /usr/bin/python3 && -r /usr/local/lib/vpn-stack/admin_apply.py ]]; then",
            "    /usr/bin/python3 /usr/local/lib/vpn-stack/admin_apply.py --add-adaptive-cidr \"${host}/32\" --adaptive-outbound to-foreign --adaptive-reason \"${reason}\" --adaptive-ttl 86400 --no-restart >/dev/null 2>&1",
            "    return $?",
            "  fi",
            "  return 1",
            "}",
            "remove_adaptive_ipv4_literal_rule() {",
            '  local host="$1"',
            "  if [[ -x /usr/bin/python3 && -r /usr/local/lib/vpn-stack/admin_apply.py ]]; then",
            "    /usr/bin/python3 /usr/local/lib/vpn-stack/admin_apply.py --remove-adaptive-cidr \"${host}/32\" --no-restart >/dev/null 2>&1",
            "    return $?",
            "  fi",
            "  return 1",
            "}",
            "apply_adaptive_routing_rules() {",
            "  if [[ -x /usr/bin/python3 && -r /usr/local/lib/vpn-stack/admin_apply.py ]]; then",
            "    /usr/bin/python3 /usr/local/lib/vpn-stack/admin_apply.py --no-restart >/dev/null 2>&1 || return 1",
            "    systemctl restart sing-box >/dev/null 2>&1 || true",
            "    return 0",
            "  fi",
            "  return 1",
            "}",
            "maybe_adapt_ipv4_literal_route() {",
            '  local top_dest="$1"',
            '  local parsed="" host="" port=""',
            '  parsed="$(adaptive_ipv4_from_top_dest "${top_dest}")"',
            '  [[ -n "${parsed}" ]] || return 0',
            '  read -r host port <<<"${parsed}"',
            '  if adaptive_ipv4_literal_is_live "${host}" "${port}"; then',
            '    if write_adaptive_ipv4_literal_rule "${host}" "ipv4_literal_slow_live:${top_dest}" && apply_adaptive_routing_rules; then',
            '      printf "ipv4_literal_adapted=%s:%s\\n" "${host}" "${port}"',
            "    fi",
            "  fi",
            "}",
            "maybe_drop_adaptive_ipv4_route() {",
            '  local top_dest="$1"',
            '  local parsed="" host="" port=""',
            '  parsed="$(adaptive_ipv4_from_top_dest "${top_dest}")"',
            '  [[ -n "${parsed}" ]] || return 0',
            '  read -r host port <<<"${parsed}"',
            '  if grep -q "\\"value\\": \\"${host}/32\\"" /var/lib/vpn-stack/adaptive-routing-rules.json 2>/dev/null; then',
            '    if remove_adaptive_ipv4_literal_rule "${host}" && apply_adaptive_routing_rules; then',
            '      printf "ipv4_literal_adaptive_dropped=%s:%s\\n" "${host}" "${port}"',
            "    fi",
            "  fi",
            "}",
            "collect_route_fail_reasons() {",
            '  [[ "${ROLE}" == "ru-gateway" ]] || return 0',
            "  command -v journalctl >/dev/null 2>&1 || return 0",
            f'  local recent_log="" journal_since="" {declarations}',
            '  journal_since="$(route_fail_journal_since)"',
            "  set +o pipefail",
            f'  recent_log="$(journalctl -u sing-box --since "${{journal_since}}" --no-pager -o cat 2>/dev/null | grep -E {_shell_single_quote(union_pattern)} || true)"',
            "  set -o pipefail",
            '  if [[ -z "${recent_log}" ]]; then',
            reset_lines,
            "    return 0",
            "  fi",
            count_lines,
            top_lines,
            decision_lines,
            "}",
        ]
    )


def render_route_fail_cache_read_shell() -> str:
    lines = ['route_fail_cache_ttl_seconds="$(cache_value ROUTE_FAIL_CACHE_TTL_SECONDS)"']
    for route_class in ROUTE_FAIL_CLASSES:
        prefix = route_class.cache_prefix
        name = route_class.name
        last_epoch_var = "${route_fail_" + name + "_last_epoch}"
        lines.extend(
            [
                f'route_fail_{name}_count="$(cache_value ROUTE_FAIL_{prefix}_COUNT)"',
                f'route_fail_{name}_top_dest="$(cache_value ROUTE_FAIL_{prefix}_TOP_DEST)"',
                f'route_fail_{name}_last_at="$(cache_value ROUTE_FAIL_{prefix}_LAST_AT)"',
                f'route_fail_{name}_last_epoch="$(cache_value ROUTE_FAIL_{prefix}_LAST_EPOCH)"',
                f'route_fail_{name}_age_s="$(age_from_epoch "{last_epoch_var}")"',
            ]
        )
    return "\n".join(lines)


def render_route_fail_cache_printf_shell() -> str:
    lines = ['printf \'route_fail_cache_ttl_seconds=%s\\n\' "${route_fail_cache_ttl_seconds}"']
    for route_class in ROUTE_FAIL_CLASSES:
        name = route_class.name
        lines.extend(
            [
                f'printf \'route_fail_{name}_count=%s\\n\' "${{route_fail_{name}_count}}"',
                f'printf \'route_fail_{name}_top_dest=%s\\n\' "${{route_fail_{name}_top_dest}}"',
                f'printf \'route_fail_{name}_last_at=%s\\n\' "${{route_fail_{name}_last_at}}"',
                f'printf \'route_fail_{name}_age_s=%s\\n\' "${{route_fail_{name}_age_s}}"',
            ]
        )
    return "\n".join(lines)


def route_fail_cache_has_data(preflight: dict[str, str]) -> bool:
    return any(preflight.get(route_class.count_key) not in {"", None, "0"} for route_class in ROUTE_FAIL_CLASSES)


def route_fail_cache_fields(preflight: dict[str, str]) -> dict[str, str]:
    fields = {"route_fail_cache_ttl_seconds": preflight.get("route_fail_cache_ttl_seconds", "")}
    for route_class in ROUTE_FAIL_CLASSES:
        fields[route_class.count_key] = preflight.get(route_class.count_key, "")
        fields[route_class.top_dest_key] = preflight.get(route_class.top_dest_key, "")
        fields[route_class.age_key] = preflight.get(route_class.age_key, "")
    return fields


def format_route_fail_cache(preflight: dict[str, str]) -> str:
    ttl = preflight.get("route_fail_cache_ttl_seconds", "-")
    parts: list[str] = []
    for route_class in ROUTE_FAIL_CLASSES:
        count = preflight.get(route_class.count_key, "0") or "0"
        age = preflight.get(route_class.age_key, "-") or "-"
        top_dest = preflight.get(route_class.top_dest_key, "")
        suffix = f" {top_dest}" if top_dest else ""
        parts.append(f"{route_class.name}={count}@{age}s{suffix}")
    return f"ttl={ttl}s, " + ", ".join(parts)
