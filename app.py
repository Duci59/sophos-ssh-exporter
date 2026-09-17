"""
sophos_ssh_exporter (v4) - Prometheus exporter lay metric bang cach SSH vao
Sophos Firewall CLI.

Luong chuan (da kiem chung tren SFOS 21.5 / XGS4500):
    ssh -> "Password:" -> nhap password
        -> banner + "Select Menu Number [0-7]:" -> gui "4"
        -> banner lai + prompt "console>"          <-- PHAI NUOT CAI NAY
        -> gui lenh -> doc output den prompt "console>" ke tiep

Thay doi so voi v3:
  1. Sau khi vao Device Console, expect prompt "console>" dau tien de dong bo
     buffer. Thieu buoc nay -> output cua lenh N bi gan cho lenh N+1.
  2. Nuot dong echo cua lenh truoc khi doc output.
  3. Loc ma mau ANSI / ky tu \r truoc khi regex.

Chay thu:
    pip install -r requirements.txt
    python app.py --config config.yml --port 9200
"""

import argparse
import logging
import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import pexpect
import yaml
from flask import Flask, Response
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest, REGISTRY

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("sophos_ssh_exporter")

app = Flask(__name__)

# --------------------------------------------------------------------------
# Luong dang nhap + dieu huong menu mac dinh (hard-code)
# --------------------------------------------------------------------------
DEFAULT_NAVIGATION = [
    {"expect": r"[Pp]assword:", "send": "{password}"},
    {"expect": r"Select Menu Number", "send": "4"},
]
DEFAULT_CONSOLE_PROMPT = r"console>\s*"

# --------------------------------------------------------------------------
# Bo metric mac dinh
# --------------------------------------------------------------------------
DEFAULT_METRICS: List[Dict[str, Any]] = [
    {
        "name": "sophos_sys_ses_count",
        "help": "So luong session hien tai (tuong duong fgSysSesCount cua FortiGate)",
        "type": "raw_number",
        "command": "system diagnostics utilities connections count",
    },
    {
        "name": "sophos_sys_ses_rate1",
        "help": "Chenh lech session count so voi lan poll truoc (tuong duong fgSysSesRate1)",
        "type": "delta",
        "source_metric": "sophos_sys_ses_count",
    },
    {
        "name": "sophos_sys_version_av",
        "help": "Phien ban Sophos AV signature, dang info metric (tuong duong fgSysVersionAv)",
        "type": "field_string",
        "command": "system diagnostics show version-info",
        "label": "Sophos AV",
    },
    {
        "name": "sophos_sys_version_ips",
        "help": "Phien ban IPS/Application signatures, dang info metric (tuong duong fgSysVersionIps)",
        "type": "field_string",
        "command": "system diagnostics show version-info",
        "label": "IPS and Application signatures",
    },
]

# --------------------------------------------------------------------------
# Gauge registry
# --------------------------------------------------------------------------
_gauge_lock = threading.Lock()
_numeric_gauges: Dict[str, Gauge] = {}
_info_gauges: Dict[str, Gauge] = {}

_last_values_lock = threading.Lock()
_last_values: Dict[Tuple[str, str], float] = {}

# Nho lai chuoi version cua lan truoc de xoa series cu khi version doi
_last_info_lock = threading.Lock()
_last_info: Dict[Tuple[str, str], str] = {}


def get_numeric_gauge(name: str, help_text: str) -> Gauge:
    with _gauge_lock:
        if name not in _numeric_gauges:
            _numeric_gauges[name] = Gauge(name, help_text or name, ["instance"], registry=REGISTRY)
        return _numeric_gauges[name]


def get_info_gauge(name: str, help_text: str) -> Gauge:
    """Metric dang 'info': gia tri luon la 1, chuoi thuc su nam trong label 'version'."""
    with _gauge_lock:
        if name not in _info_gauges:
            _info_gauges[name] = Gauge(name, help_text or name, ["instance", "version"], registry=REGISTRY)
        return _info_gauges[name]


# --------------------------------------------------------------------------
# Lam sach output CLI
# --------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")


def strip_ansi(text: str) -> str:
    """Bo ma mau ANSI va \\r. Sophos to mau mot so dong (vd POP/IMAP proxy)."""
    return _ANSI_RE.sub("", text)


# --------------------------------------------------------------------------
# Trich xuat gia tri
# --------------------------------------------------------------------------

def extract_raw_number(command: str, output: str) -> Optional[float]:
    """Lay dong dau tien chi chua 1 con so (bo qua dong echo lenh va prompt)."""
    cmd = command.strip()
    for line in output.splitlines():
        line = line.strip()
        if not line or line == cmd or cmd in line:
            continue
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", line):
            return float(line)
    return None


def extract_field_string(label: str, output: str) -> Optional[str]:
    """Lay chuoi sau dau ':' cua dong bat dau bang dung nhan.

    Vi du dong that tren SFOS 21.5:
        "Sophos AV:                      1.0.21547"
        "IPS and Application signatures: 18.25.58"
    Neo ^ o dau dong de "Sophos AV" khong khop nham "Avira AV".
    """
    pattern = re.compile(
        rf"^[ \t]*{re.escape(label)}[ \t]*:[ \t]*(\S.*?)[ \t]*$",
        re.MULTILINE,
    )
    m = pattern.search(output)
    return m.group(1).strip() if m else None


def extract_field_number(label: str, output: str) -> Optional[float]:
    pattern = re.compile(
        rf"^[ \t]*{re.escape(label)}[ \t]*:[ \t]*([-+]?\d+(?:\.\d+)?)",
        re.MULTILINE,
    )
    m = pattern.search(output)
    return float(m.group(1)) if m else None


# --------------------------------------------------------------------------
# SSH / CLI automation
# --------------------------------------------------------------------------

def run_navigation(child: "pexpect.spawn", steps: list, ctx: Dict[str, Any]) -> None:
    for step in steps:
        pattern = step["expect"]
        optional = step.get("optional", False)

        if optional:
            idx = child.expect([pattern, pexpect.TIMEOUT], timeout=step.get("timeout", 5))
            if idx != 0:
                continue
        else:
            child.expect(pattern, timeout=step.get("timeout", 20))

        if "send" in step:
            child.sendline(step["send"].format(**ctx))


def send_and_capture(child: "pexpect.spawn", command: str, console_prompt: str,
                     timeout: int) -> str:
    """Gui 1 lenh, nuot dong echo, tra ve output da lam sach."""
    child.sendline(command)

    # Nuot dong echo cua chinh lenh vua gui (neu co) de no khong lot vao output
    try:
        child.expect_exact(command, timeout=5)
    except (pexpect.TIMEOUT, pexpect.EOF):
        pass

    child.expect(console_prompt, timeout=timeout)
    return strip_ansi(child.before or "")


def collect_once(target_name: str, target_cfg: Dict[str, Any], metric_defs: List[Dict[str, Any]]) -> None:
    host = target_cfg["host"]
    port = target_cfg.get("port", 22)
    username = target_cfg["username"]
    ssh_cmd = (
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-p {port} {username}@{host}"
    )

    navigation = target_cfg.get("menu_navigation", DEFAULT_NAVIGATION)
    console_prompt = target_cfg.get("console_prompt", DEFAULT_CONSOLE_PROMPT)
    cmd_timeout = target_cfg.get("command_timeout", 20)

    child = pexpect.spawn(ssh_cmd, timeout=target_cfg.get("connect_timeout", 20), encoding="utf-8")
    success_gauge = get_numeric_gauge("sophos_ssh_scrape_success", "1 neu lan poll gan nhat thanh cong")
    last_ts_gauge = get_numeric_gauge("sophos_ssh_last_scrape_timestamp_seconds",
                                      "Unix timestamp cua lan poll gan nhat")

    try:
        run_navigation(child, navigation, target_cfg)

        # ------------------------------------------------------------------
        # QUAN TRONG: sau khi chon "4", Sophos in lai banner
        # (Firmware Version / Model / Hostname) roi moi ra prompt "console>".
        # Phai doc het cho den prompt dau tien nay, neu khong lan expect
        # ke tiep se khop nham prompt cu -> output bi lech mot nhip
        # (metric A nhan output cua banner, metric B nhan output cua lenh A).
        # ------------------------------------------------------------------
        child.expect(console_prompt, timeout=cmd_timeout)
        log.debug("[%s] Da vao Device Console", target_name)

        # Gom metric theo lenh: moi lenh chi chay 1 lan, ap dung nhieu
        # phep trich xuat len cung 1 output.
        commands_needed: Dict[str, List[Dict[str, Any]]] = {}
        for m in metric_defs:
            if m["type"] in ("raw_number", "field_string", "field_number"):
                commands_needed.setdefault(m["command"], []).append(m)

        values_this_poll: Dict[str, Any] = {}

        for command, defs in commands_needed.items():
            output = send_and_capture(child, command, console_prompt, cmd_timeout)

            for m in defs:
                mtype = m["type"]
                if mtype == "raw_number":
                    value = extract_raw_number(command, output)
                elif mtype == "field_string":
                    value = extract_field_string(m["label"], output)
                elif mtype == "field_number":
                    value = extract_field_number(m["label"], output)
                else:
                    value = None

                if value is None:
                    log.warning("[%s] khong trich xuat duoc metric '%s' tu lenh '%s'. Output:\n%s",
                                target_name, m["name"], command, output)
                    continue

                values_this_poll[m["name"]] = value

                if mtype == "field_string":
                    gauge = get_info_gauge(m["name"], m.get("help", ""))
                    key = (target_name, m["name"])
                    with _last_info_lock:
                        old = _last_info.get(key)
                        _last_info[key] = value
                    # Version doi -> xoa series cu, tranh ton tai 2 series cung luc
                    if old is not None and old != value:
                        try:
                            gauge.remove(target_name, old)
                        except KeyError:
                            pass
                    gauge.labels(target_name, value).set(1)
                    log.info("[%s] %s{version=%r} = 1", target_name, m["name"], value)
                else:
                    gauge = get_numeric_gauge(m["name"], m.get("help", ""))
                    gauge.labels(target_name).set(value)
                    log.info("[%s] %s = %s", target_name, m["name"], value)

        # Metric dang "delta"
        for m in metric_defs:
            if m["type"] != "delta":
                continue
            src_name = m["source_metric"]
            current = values_this_poll.get(src_name)
            if current is None:
                continue

            key = (target_name, src_name)
            with _last_values_lock:
                previous = _last_values.get(key)
                _last_values[key] = current

            if previous is not None:
                delta = current - previous
                gauge = get_numeric_gauge(m["name"], m.get("help", ""))
                gauge.labels(target_name).set(delta)
                log.info("[%s] %s = %s (delta)", target_name, m["name"], delta)

        # Thoat gon gang: exit ve Main Menu roi chon 0
        try:
            child.sendline("exit")
            child.expect("Select Menu Number", timeout=5)
            child.sendline("0")
        except (pexpect.TIMEOUT, pexpect.EOF):
            pass

        success_gauge.labels(target_name).set(1)

    except Exception as exc:  # noqa: BLE001
        log.error("[%s] Loi khi poll qua SSH: %s", target_name, exc)
        success_gauge.labels(target_name).set(0)

    finally:
        last_ts_gauge.labels(target_name).set(time.time())
        child.close(force=True)


def poller_loop(target_name: str, target_cfg: Dict[str, Any], metric_defs: List[Dict[str, Any]]) -> None:
    interval = target_cfg.get("poll_interval", 30)
    while True:
        try:
            collect_once(target_name, target_cfg, metric_defs)
        except Exception as exc:  # noqa: BLE001 - khong de thread chet
            log.error("[%s] Loi khong mong doi trong poller_loop: %s", target_name, exc)
        time.sleep(interval)


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

@app.route("/metrics")
def metrics():
    return Response(generate_latest(REGISTRY), mimetype=CONTENT_TYPE_LATEST)


@app.route("/")
def index():
    return '<h3>sophos_ssh_exporter</h3><p><a href="/metrics">/metrics</a></p>'


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(description="Sophos Firewall SSH-CLI Prometheus exporter")
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--port", type=int, default=9200)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true", help="Bat log DEBUG")
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)

    cfg = load_config(args.config)
    global_metrics = cfg.get("metrics") or DEFAULT_METRICS

    for target in cfg.get("targets", []):
        metric_defs = target.get("metrics", global_metrics)
        t = threading.Thread(
            target=poller_loop, args=(target["name"], target, metric_defs), daemon=True
        )
        t.start()
        log.info("Da khoi dong poller cho target '%s' (moi %ss, %d metric)",
                 target["name"], target.get("poll_interval", 30), len(metric_defs))

    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
