"""
sophos_ssh_exporter (v5) - Prometheus exporter lay metric bang cach SSH vao
Sophos Firewall CLI. Tich hop them kha nang lay thong tin SFP quang tu Advanced Shell.
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
        "help": "So luong session hien tai",
        "type": "raw_number",
        "command": "system diagnostics utilities connections count",
    },
    {
        "name": "sophos_sys_ses_rate1",
        "help": "Chenh lech session count so voi lan poll truoc",
        "type": "delta",
        "source_metric": "sophos_sys_ses_count",
    },
    {
        "name": "sophos_sys_version_av",
        "help": "Phien ban Sophos AV signature",
        "type": "field_string",
        "command": "system diagnostics show version-info",
        "label": "Sophos AV",
    },
    {
        "name": "sophos_sys_version_ips",
        "help": "Phien ban IPS/Application signatures",
        "type": "field_string",
        "command": "system diagnostics show version-info",
        "label": "IPS and Application signatures",
    },
    {
        "name": "sfp_inventory",
        "help": "Lay thong tin SFP quang tu Advanced Shell (ethtool -m)",
        "type": "sfp_inventory",
    }
]

# --------------------------------------------------------------------------
# Gauge registry
# --------------------------------------------------------------------------
_gauge_lock = threading.Lock()
_numeric_gauges: Dict[str, Gauge] = {}
_info_gauges: Dict[str, Gauge] = {}

_last_values_lock = threading.Lock()
_last_values: Dict[Tuple[str, str], float] = {}

_last_info_lock = threading.Lock()
_last_info: Dict[Tuple[str, str], str] = {}

_last_sfp_info_lock = threading.Lock()
_last_sfp_info: Dict[Tuple[str, str], Tuple[str, str, str]] = {}


def get_numeric_gauge(name: str, help_text: str) -> Gauge:
    with _gauge_lock:
        if name not in _numeric_gauges:
            _numeric_gauges[name] = Gauge(name, help_text or name, ["instance"], registry=REGISTRY)
        return _numeric_gauges[name]


def get_info_gauge(name: str, help_text: str) -> Gauge:
    with _gauge_lock:
        if name not in _info_gauges:
            _info_gauges[name] = Gauge(name, help_text or name, ["instance", "version"], registry=REGISTRY)
        return _info_gauges[name]

# --------------------------------------------------------------------------
# Gauge rieng cho SFP Inventory ghep lai theo rule
# --------------------------------------------------------------------------
SFP_COMMON_LABELS = ["device_name", "device_type", "entPhysicalIndex", "instance", "job", "vendor"]

def get_sfp_gauge(metric_name: str, value_label: str) -> Gauge:
    with _gauge_lock:
        if metric_name not in _info_gauges:
            _info_gauges[metric_name] = Gauge(
                metric_name,
                f"SFP {metric_name} info",
                SFP_COMMON_LABELS + [value_label],
                registry=REGISTRY
            )
        return _info_gauges[metric_name]


# --------------------------------------------------------------------------
# Lam sach output CLI & Trich xuat gia tri
# --------------------------------------------------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r")

def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def extract_raw_number(command: str, output: str) -> Optional[float]:
    cmd = command.strip()
    for line in output.splitlines():
        line = line.strip()
        if not line or line == cmd or cmd in line:
            continue
        if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", line):
            return float(line)
    return None


def extract_field_string(label: str, output: str) -> Optional[str]:
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


def send_and_capture(child: "pexpect.spawn", command: str, console_prompt: str, timeout: int) -> str:
    child.sendline(command)
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
    last_ts_gauge = get_numeric_gauge("sophos_ssh_last_scrape_timestamp_seconds", "Unix timestamp cua lan poll gan nhat")

    has_sfp = any(m.get("type") == "sfp_inventory" for m in metric_defs)

    try:
        run_navigation(child, navigation, target_cfg)
        child.expect(console_prompt, timeout=cmd_timeout)
        
        # --- 1. THU THAP METRIC TREN DEVICE CONSOLE ---
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
                    continue

                values_this_poll[m["name"]] = value
                if mtype == "field_string":
                    gauge = get_info_gauge(m["name"], m.get("help", ""))
                    key = (target_name, m["name"])
                    with _last_info_lock:
                        old = _last_info.get(key)
                        _last_info[key] = value
                    if old is not None and old != value:
                        try:
                            gauge.remove(target_name, old)
                        except KeyError:
                            pass
                    gauge.labels(target_name, value).set(1)
                else:
                    gauge = get_numeric_gauge(m["name"], m.get("help", ""))
                    gauge.labels(target_name).set(value)

        # Xy ly metric delta
        for m in metric_defs:
            if m["type"] == "delta":
                src_name = m["source_metric"]
                current = values_this_poll.get(src_name)
                if current is None: continue
                key = (target_name, src_name)
                with _last_values_lock:
                    previous = _last_values.get(key)
                    _last_values[key] = current
                if previous is not None:
                    delta = current - previous
                    gauge = get_numeric_gauge(m["name"], m.get("help", ""))
                    gauge.labels(target_name).set(delta)

        # Thoat khoi Device Console de ve Main Menu
        try:
            child.sendline("exit")
            child.expect("Select Menu Number", timeout=5)
        except (pexpect.TIMEOUT, pexpect.EOF):
            pass

        # --- 2. THU THAP SFP TREN ADVANCED SHELL ---
        if has_sfp:
            try:
                child.sendline("5")
                child.expect("Select Menu Number", timeout=5)
                child.sendline("3")
                child.expect(r"#\s*", timeout=5)
                
                sfp_ports = [f"PortA{i}" for i in range(1, 9)] + [f"PortF{i}" for i in range(1, 5)] + [f"PortB{i}" for i in range(1, 5)]
                for i, port in enumerate(sfp_ports, start=1):
                    idx = str(i)
                    cmd = f"ethtool -m {port}"
                    child.sendline(cmd)
                    
                    try:
                        child.expect_exact(cmd, timeout=2)
                    except (pexpect.TIMEOUT, pexpect.EOF):
                        pass
                    
                    child.expect(r"#\s*", timeout=10)
                    out = strip_ansi(child.before or "")
                    
                    mfg = extract_field_string("Vendor name", out)
                    pn = extract_field_string("Vendor PN", out)
                    
                    if mfg and pn:
                        key = (target_name, idx)
                        with _last_sfp_info_lock:
                            old_data = _last_sfp_info.get(key)
                            if old_data:
                                old_mfg, old_pn, old_port = old_data
                                if old_mfg != mfg or old_pn != pn or old_port != port:
                                    try:
                                        get_sfp_gauge("entPhysicalMfgName", "entPhysicalMfgName").remove(target_name, "firewall", idx, host, "firewall", "sophos", old_mfg)
                                        get_sfp_gauge("entPhysicalModelName", "entPhysicalModelName").remove(target_name, "firewall", idx, host, "firewall", "sophos", old_pn)
                                        get_sfp_gauge("entPhysicalName", "entPhysicalName").remove(target_name, "firewall", idx, host, "firewall", "sophos", old_port)
                                    except KeyError:
                                        pass
                            _last_sfp_info[key] = (mfg, pn, port)
                            
                        get_sfp_gauge("entPhysicalMfgName", "entPhysicalMfgName").labels(target_name, "firewall", idx, host, "firewall", "sophos", mfg).set(1)
                        get_sfp_gauge("entPhysicalModelName", "entPhysicalModelName").labels(target_name, "firewall", idx, host, "firewall", "sophos", pn).set(1)
                        get_sfp_gauge("entPhysicalName", "entPhysicalName").labels(target_name, "firewall", idx, host, "firewall", "sophos", port).set(1)
                
                # Thoat Advanced Shell ve Main Menu
                child.sendline("exit")
                child.expect("Select Menu Number", timeout=5)
            except Exception as e:
                log.warning("[%s] Loi khi lay SFP info: %s", target_name, e)

        # Ket thuc Session SSH
        try:
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
        except Exception as exc:  # noqa: BLE001
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
    return '<h3>sophos_ssh_exporter v5</h3><p><a href="/metrics">/metrics</a></p>'


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