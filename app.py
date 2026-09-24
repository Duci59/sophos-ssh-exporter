"""
sophos_ssh_exporter (v7 - On-Demand & Hardcoded Metrics - SFP Bug Fixed)
"""

import argparse
import logging
import re
import threading
import time
from typing import Any, Dict, Optional

import pexpect
import yaml
from flask import Flask, Response, request
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, CollectorRegistry, generate_latest

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("sophos_ssh_exporter")

app = Flask(__name__)
CONFIG_DATA = {}

DEFAULT_NAVIGATION = [
    {"expect": r"[Pp]assword:", "send": "{password}"},
    {"expect": r"Select Menu Number", "send": "4"},
]
DEFAULT_CONSOLE_PROMPT = r"console>\s*"
SFP_COMMON_LABELS = ["device_name", "device_type", "entPhysicalIndex", "instance", "job", "vendor"]

# --- DANH SACH METRIC DUOC FIX CUNG TRONG CODE ---
BUILTIN_METRICS = [
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
        "help": "Lay thong tin SFP quang tu Advanced Shell",
        "type": "sfp_inventory",
    }
]

# State de luu tru gia tri truoc do cho cac metric dang "delta"
_state_lock = threading.Lock()
_target_state: Dict[str, Dict[str, float]] = {}

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
    pattern = re.compile(rf"^[ \t]*{re.escape(label)}[ \t]*:[ \t]*(\S.*?)[ \t]*$", re.MULTILINE)
    m = pattern.search(output)
    return m.group(1).strip() if m else None

def extract_field_number(label: str, output: str) -> Optional[float]:
    pattern = re.compile(rf"^[ \t]*{re.escape(label)}[ \t]*:[ \t]*([-+]?\d+(?:\.\d+)?)", re.MULTILINE)
    m = pattern.search(output)
    return float(m.group(1)) if m else None

def run_navigation(child: "pexpect.spawn", steps: list, ctx: Dict[str, Any]) -> None:
    for step in steps:
        pattern = step["expect"]
        if step.get("optional", False):
            idx = child.expect([pattern, pexpect.TIMEOUT], timeout=step.get("timeout", 5))
            if idx != 0: continue
        else:
            child.expect(pattern, timeout=step.get("timeout", 20))
        if "send" in step:
            child.sendline(step["send"].format(**ctx))

def send_and_capture(child: "pexpect.spawn", command: str, console_prompt: str, timeout: int) -> str:
    child.sendline(command)
    try:
        child.expect_exact(command, timeout=5)
    except: pass
    child.expect(console_prompt, timeout=timeout)
    return strip_ansi(child.before or "")

def collect_from_target(target_ip: str, module_cfg: Dict[str, Any], registry: CollectorRegistry) -> None:
    port = module_cfg.get("port", 22)
    username = module_cfg["username"]
    ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {port} {username}@{target_ip}"
    
    cmd_timeout = module_cfg.get("command_timeout", 20)
    console_prompt = module_cfg.get("console_prompt", DEFAULT_CONSOLE_PROMPT)
    has_sfp = any(m.get("type") == "sfp_inventory" for m in BUILTIN_METRICS)

    success_gauge = Gauge("sophos_ssh_scrape_success", "Scrape success", ["instance"], registry=registry)
    duration_gauge = Gauge("sophos_ssh_scrape_duration_seconds", "Scrape duration", ["instance"], registry=registry)
    
    start_time = time.time()
    child = pexpect.spawn(ssh_cmd, timeout=module_cfg.get("connect_timeout", 20), encoding="utf-8")
    
    try:
        run_navigation(child, module_cfg.get("menu_navigation", DEFAULT_NAVIGATION), module_cfg)
        child.expect(console_prompt, timeout=cmd_timeout)
        
        commands_needed = {}
        for m in BUILTIN_METRICS:
            if m["type"] in ("raw_number", "field_string", "field_number"):
                commands_needed.setdefault(m["command"], []).append(m)
        
        values_this_poll = {}
        
        # --- 1. GET DEVICE CONSOLE METRICS ---
        for command, defs in commands_needed.items():
            output = send_and_capture(child, command, console_prompt, cmd_timeout)
            for m in defs:
                mtype = m["type"]
                if mtype == "raw_number": value = extract_raw_number(command, output)
                elif mtype == "field_string": value = extract_field_string(m["label"], output)
                elif mtype == "field_number": value = extract_field_number(m["label"], output)
                else: value = None
                
                if value is None: continue
                values_this_poll[m["name"]] = value
                
                if mtype == "field_string":
                    g = Gauge(m["name"], m.get("help", ""), ["instance", "version"], registry=registry)
                    g.labels(instance=target_ip, version=value).set(1)
                else:
                    g = Gauge(m["name"], m.get("help", ""), ["instance"], registry=registry)
                    g.labels(instance=target_ip).set(value)
        
        # Xu ly Metric dang Delta (tinh toan chenh lech)
        with _state_lock:
            if target_ip not in _target_state:
                _target_state[target_ip] = {}
            for m in BUILTIN_METRICS:
                if m["type"] == "delta":
                    src_name = m["source_metric"]
                    current = values_this_poll.get(src_name)
                    if current is None: continue
                    previous = _target_state[target_ip].get(src_name)
                    _target_state[target_ip][src_name] = current
                    if previous is not None:
                        delta = current - previous
                        g = Gauge(m["name"], m.get("help", ""), ["instance"], registry=registry)
                        g.labels(instance=target_ip).set(delta)

        try:
            child.sendline("exit")
            child.expect("Select Menu Number", timeout=5)
        except: pass

        # --- 2. GET ADVANCED SHELL SFP METRICS ---
        if has_sfp:
            try:
                child.sendline("5")
                child.expect("Select Menu Number", timeout=5)
                child.sendline("3")
                child.expect(r"#\s*", timeout=5)
                
                # Khoi tao metric chi 1 lan duy nhat cho moi request tranh loi duplicate registry
                g_mfg = Gauge("entPhysicalMfgName", "SFP Mfg", SFP_COMMON_LABELS + ["entPhysicalMfgName"], registry=registry)
                g_mdl = Gauge("entPhysicalModelName", "SFP Model", SFP_COMMON_LABELS + ["entPhysicalModelName"], registry=registry)
                g_name = Gauge("entPhysicalName", "SFP Name", SFP_COMMON_LABELS + ["entPhysicalName"], registry=registry)

                sfp_ports = [f"PortA{i}" for i in range(1, 9)] + [f"PortF{i}" for i in range(1, 5)] + [f"PortB{i}" for i in range(1, 5)]
                for i, port in enumerate(sfp_ports, start=1):
                    idx = str(i)
                    cmd = f"ethtool -m {port}"
                    child.sendline(cmd)
                    try: child.expect_exact(cmd, timeout=2)
                    except: pass
                    
                    child.expect(r"#\s*", timeout=10)
                    out = strip_ansi(child.before or "")
                    
                    mfg = extract_field_string("Vendor name", out)
                    pn = extract_field_string("Vendor PN", out)
                    
                    if mfg and pn:
                        g_mfg.labels(device_name=target_ip, device_type="firewall", entPhysicalIndex=idx, instance=target_ip, job="firewall", vendor="sophos", entPhysicalMfgName=mfg).set(1)
                        g_mdl.labels(device_name=target_ip, device_type="firewall", entPhysicalIndex=idx, instance=target_ip, job="firewall", vendor="sophos", entPhysicalModelName=pn).set(1)
                        g_name.labels(device_name=target_ip, device_type="firewall", entPhysicalIndex=idx, instance=target_ip, job="firewall", vendor="sophos", entPhysicalName=port).set(1)
                
                child.sendline("exit")
                child.expect("Select Menu Number", timeout=5)
            except Exception as e:
                log.warning("[%s] Loi SFP: %s", target_ip, e)

        try: child.sendline("0")
        except: pass

        success_gauge.labels(instance=target_ip).set(1)

    except Exception as exc:
        log.error("[%s] Loi SSH: %s", target_ip, exc)
        success_gauge.labels(instance=target_ip).set(0)
    finally:
        duration_gauge.labels(instance=target_ip).set(time.time() - start_time)
        child.close(force=True)

@app.route("/scrape")
def scrape():
    target = request.args.get("target")
    module_name = request.args.get("module", "default")
    if not target:
        return "Missing 'target' parameter", 400
    if module_name not in CONFIG_DATA.get("modules", {}):
        return f"Module '{module_name}' not found", 404
        
    registry = CollectorRegistry()
    collect_from_target(target, CONFIG_DATA["modules"][module_name], registry)
    return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

@app.route("/")
def index():
    return '<h3>sophos_ssh_exporter v7</h3><p><a href="/scrape?target=1.2.3.4">/scrape?target=1.2.3.4</a></p>'

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yml")
    parser.add_argument("--port", type=int, default=9200)
    args = parser.parse_args()
    
    with open(args.config, "r", encoding="utf-8") as f:
        CONFIG_DATA = yaml.safe_load(f)
        
    app.run(host="0.0.0.0", port=args.port, threaded=True)