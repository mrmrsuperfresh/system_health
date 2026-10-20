#!/usr/bin/env python3
"""
Ubuntu 24.04 System Health Diagnostic Script

Read-only -- gathers CPU, memory, temperature, disk, and network metrics
from /proc, /sys, and standard Linux interfaces without modifying anything.

Usage:
    python3 system_health.py [--json] [--interval SECONDS]

Options:
    --json          Output in JSON format instead of human-readable table
    --interval SEC  Seconds to wait between two CPU/disk busy snapshots
                    (default: 1, controls measurement window)
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── colour helpers ──────────────────────────────────────────────────────
class _C:
    """ANSI colour codes (disabled if stdout is not a terminal)."""
    _enabled = sys.stdout.isatty()

    @staticmethod
    def reset() -> str:
        return "" if not _C._enabled else "\033[0m"

    @staticmethod
    def red() -> str:
        return "" if not _C._enabled else "\033[91m"

    @staticmethod
    def yellow() -> str:
        return "" if not _C._enabled else "\033[93m"

    @staticmethod
    def green() -> str:
        return "" if not _C._enabled else "\033[92m"

    @staticmethod
    def bold() -> str:
        return "" if not _C._enabled else "\033[1m"


def _status(score: float | None, high_is_bad: bool = True) -> str:
    """Return a colour tag based on a numeric score (0-100)."""
    if score is None:
        return "N/A"
    if high_is_bad:
        if score >= 90:
            return f"{_C.red()}CRITICAL{_C.reset()}"
        if score >= 75:
            return f"{_C.yellow()}WARNING{_C.reset()}"
        return f"{_C.green()}OK{_C.reset()}"
    else:
        if score < 10:
            return f"{_C.red()}CRITICAL{_C.reset()}"
        if score < 25:
            return f"{_C.yellow()}WARNING{_C.reset()}"
        return f"{_C.green()}OK{_C.reset()}"



def _human_bytes(value: float | int) -> str:
    """Convert a byte value to the most appropriate human-readable unit."""
    if not isinstance(value, (int, float)) or value < 0:
        return "N/A"
    if value == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    v = float(value)
    while v >= 1024 and idx < len(units) - 1:
        v /= 1024
        idx += 1
    if idx == 0:
        return f"{int(v)} {units[idx]}"
    return f"{v:.1f} {units[idx]}"


# Interfaces excluded from penalty/issue lists but shown in tables
CONTAINER_IFACE_PREFIXES = ("docker", "br-", "veth", "lxc", "virbr")
LOOPBACK = "lo"

# ── CPU ─────────────────────────────────────────────────────────────────

def _read_cpu_times() -> dict[str, dict[str, int]]:
    """Parse /proc/stat and return cumulative jiffies per CPU."""
    result: dict[str, dict[str, int]] = {}
    with open("/proc/stat") as f:
        for line in f:
            if not line.startswith("cpu"):
                continue
            cpu_key = line.split()[0]
            if cpu_key == "cpu":          # skip the aggregate row -- only want per-core
                continue
            parts = line.split()
            cpu_name = parts[0]
            values = [int(v) for v in parts[1:]]
            idle = values[3] + values[4] if len(values) > 4 else values[3]
            total = sum(values)
            result[cpu_name] = {"idle": idle, "total": total}
    return result


def cpu_health(interval: float = 1.0) -> dict[str, Any]:
    """Measure CPU utilisation and load average."""
    before = _read_cpu_times()
    time.sleep(interval)
    after = _read_cpu_times()

    idle_b = sum(v["idle"] for v in before.values())
    total_b = sum(v["total"] for v in before.values())
    idle_a = sum(v["idle"] for v in after.values())
    total_a = sum(v["total"] for v in after.values())

    idle_d = idle_a - idle_b
    total_d = total_a - total_b
    cpu_pct = round((1 - idle_d / total_d) * 100, 1) if total_d else 0.0

    cores: list[dict[str, Any]] = []
    for name in before:
        i_d = after[name]["idle"] - before[name]["idle"]
        t_d = after[name]["total"] - before[name]["total"]
        pct = round((1 - i_d / t_d) * 100, 1) if t_d else 0.0
        cores.append({"core": name, "percent": pct})

    loadavg_parts = Path("/proc/loadavg").read_text().split()
    load_1, load_5, load_15 = (float(v) for v in loadavg_parts[:3])
    ncpu = os.cpu_count() or 1
    cpu_score = max(0, round(min(100 - (load_1 / ncpu) * 100, 100), 1))

    freq = None
    try:
        freq_base = Path("/sys/devices/system/cpu/cpufreq/policy0")
        if freq_base.exists():
            cur = float((freq_base / "scaling_cur_freq").read_text().strip()) / 1000
            mx = float((freq_base / "scaling_max_freq").read_text().strip()) / 1000
            freq = {"current_ghz": round(cur, 2), "max_ghz": round(mx, 2)}
    except Exception:
        pass

    return {
        "percent": cpu_pct,
        "score": cpu_score,
        "cores": cores,
        "load_average": {"1m": load_1, "5m": load_5, "15m": load_15},
        "logical_cpus": ncpu,
        "frequency_ghz": freq,
    }


# ── Memory ──────────────────────────────────────────────────────────────

def memory_health() -> dict[str, Any]:
    """Parse /proc/meminfo for a detailed memory snapshot."""
    meminfo: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        parts = line.split()
        key = parts[0].rstrip(":")
        meminfo[key] = int(parts[1])

    total_kb = meminfo.get("MemTotal", 0)
    avail_kb = meminfo.get("MemAvailable", 0)
    free_kb = meminfo.get("MemFree", 0)
    used_kb = total_kb - avail_kb
    cached_kb = meminfo.get("Cached", 0) + meminfo.get("SReclaimable", 0)
    buffers_kb = meminfo.get("Buffers", 0)
    active_kb = meminfo.get("Active", 0)
    inactive_kb = meminfo.get("Inactive", 0)
    slab_kb = meminfo.get("Slab", 0)

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = swap_total - swap_free

    avail_pct = round(avail_kb / total_kb * 100, 1) if total_kb else 100.0
    used_pct = round(used_kb / total_kb * 100, 1) if total_kb else 0.0

    return {
        "total_gb": round(total_kb / 1_048_576, 1),
        "used_gb": round(used_kb / 1_048_576, 1),
        "available_gb": round(avail_kb / 1_048_576, 1),
        "free_gb": round(free_kb / 1_048_576, 1),
        "cached_gb": round(cached_kb / 1_048_576, 1),
        "buffers_gb": round(buffers_kb / 1_048_576, 1),
        "active_gb": round(active_kb / 1_048_576, 1),
        "inactive_gb": round(inactive_kb / 1_048_576, 1),
        "slab_gb": round(slab_kb / 1_048_576, 1),
        "used_percent": used_pct,
        "available_percent": avail_pct,
        "score": avail_pct,
        "swap_total_gb": round(swap_total / 1_048_576, 1),
        "swap_used_gb": round(swap_used / 1_048_576, 1),
        "swap_percent": round(swap_used / swap_total * 100, 1) if swap_total else 0.0,
    }


# ── Temperature ─────────────────────────────────────────────────────────

def temperature_health() -> dict[str, Any]:
    """Read temperatures from /sys/class/thermal."""
    temps: list[dict[str, Any]] = []

    thermal_dir = Path("/sys/class/thermal")
    if thermal_dir.exists():
        for tz in sorted(thermal_dir.iterdir()):
            if not tz.is_dir() or not tz.name.startswith("thermal_zone"):
                continue
            try:
                type_path = tz / "type"
                temp_path = tz / "temp"
                if type_path.exists() and temp_path.exists():
                    label = type_path.read_text().strip()
                    value_milli = int(temp_path.read_text().strip())
                    value_c = round(value_milli / 1000, 1)
                    critical = min(105.0, max(value_c + 20, 90.0))
                    pct = round(min((value_c / critical) * 100, 100), 1) if critical else 0
                    temps.append({"zone": tz.name, "label": label, "celsius": value_c})
            except Exception:
                continue

    if not temps:
        return {"zones": [], "error": "No temperature sensors found (may be a VM/container)", "score": None}

    max_temp = max(t["celsius"] for t in temps)
    score = max(0, round(min((1 - (max_temp - 50) / 45) * 100, 100), 1)) if max_temp >= 0 else None

    return {"zones": temps, "score": score}


# ── Disk ────────────────────────────────────────────────────────────────

def disk_health(interval: float = 1.0) -> dict[str, Any]:
    """Collect per-partition usage and I/O statistics."""
    partitions: list[dict[str, Any]] = []
    skip_fs = {"proc", "sysfs", "devtmpfs", "devpts", "tmpfs",
               "debugfs", "securityfs", "cgroup", "cgroup2",
               "pstore", "bpf", "autofs", "mqueue", "hugetlbfs",
               "configfs", "fusectl", "tracefs",
               # virtual / read-only filesystems -- not meaningful for health scoring
               "squashfs", "nsfs", "binfmt_misc", "efivarfs"}
    skip_mount_prefixes = ("/run/snapd/ns/",)

    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            dev, mp, fstype = parts[0], parts[1], parts[2]
            if fstype in skip_fs or any(mp.startswith(p) for p in skip_mount_prefixes) or mp in {p["mountpoint"] for p in partitions}:
                continue

            try:
                st = os.statvfs(mp)
                total = st.f_frsize * st.f_blocks
                free_avail = st.f_frsize * st.f_bavail
                used = total - (st.f_frsize * st.f_bfree)

                used_pct = round(used / total * 100, 1) if total else 0.0
                avail_pct = round(free_avail / total * 100, 1) if total else 100.0

                partitions.append({
                    "device": dev,
                    "mountpoint": mp,
                    "fstype": fstype,
                    "total_gb": round(total / 1_073_741_824, 1),
                    "used_gb": round(used / 1_073_741_824, 1),
                    "available_gb": round(free_avail / 1_073_741_824, 1),
                    "used_percent": used_pct,
                    "score": min(avail_pct, 100.0),
                })
            except (OSError, PermissionError):
                continue
    except Exception:
        pass

    io_total = {"reads": 0, "writes": 0, "read_bytes": 0, "write_bytes": 0}
    try:
        before_text = Path("/proc/diskstats").read_text()
        time.sleep(interval)
        after_text = Path("/proc/diskstats").read_text()

        def _sum_busy(text: str) -> int:
            tb = 0
            for line in text.splitlines():
                parts = line.split()
                if len(parts) >= 14:
                    try:
                        tb += int(parts[12])
                    except ValueError:
                        pass
            return tb

        for line in after_text.splitlines():
            parts = line.split()
            if len(parts) < 14:
                continue
            try:
                reads = int(parts[3])
                writes = int(parts[7])
                r_sectors = int(parts[5])
                w_sectors = int(parts[9])
                io_total["reads"] += reads
                io_total["writes"] += writes
                io_total["read_bytes"] += r_sectors * 512
                io_total["write_bytes"] += w_sectors * 512
            except (ValueError, IndexError):
                continue

        busy_before = _sum_busy(before_text)
        busy_after = _sum_busy(after_text)
        busy_ms = max(0, busy_after - busy_before)
        max_possible = interval * 1000
        overall_busy_pct = round(min(busy_ms / max_possible * 100, 100), 1) if max_possible else 0.0
    except Exception:
        overall_busy_pct = None

    space_scores = [p["score"] for p in partitions]
    avg_space = round(sum(space_scores) / len(space_scores), 1) if space_scores else 50.0
    if overall_busy_pct is not None:
        io_score = max(0, 100 - overall_busy_pct)
        overall = round(avg_space * 0.7 + io_score * 0.3, 1)
    else:
        overall = avg_space

    return {
        "partitions": partitions,
        "io_total": io_total,
        "overall_disk_busy_percent": overall_busy_pct,
        "score": overall,
    }


# ── Network ─────────────────────────────────────────────────────────────

def _parse_cidr_addrs(output: str) -> list[str]:
    """Extract IPv4 addresses with CIDR from 'ip -4 addr show' output."""
    addrs: list[str] = []
    for line in output.splitlines():
        parts = line.split()
        for i, p in enumerate(parts):
            if p == "inet" and i + 1 < len(parts):
                addrs.append(parts[i + 1])
    return addrs


def network_health() -> dict[str, Any]:
    """Assess network interface status and connectivity."""
    interfaces: list[dict[str, Any]] = []

    try:
        dev_lines = Path("/proc/net/dev").read_text().splitlines()[2:]
    except Exception:
        return {
            "interfaces": [], "dns": {"server": "?", "ok": False, "latency_ms": None},
            "internet": {"reachable": None, "target": "?", "rtt_ms": None},
            "issues": ["Could not read /proc/net/dev"], "score": 0,
        }

    for line in dev_lines:
        parts = line.split()
        if len(parts) < 17:
            continue
        iface = parts[0].rstrip(":")

        rx_bytes = int(parts[1])
        rx_packets = int(parts[2])
        rx_errs = int(parts[3])
        rx_drop = int(parts[4])
        tx_bytes = int(parts[9])
        tx_packets = int(parts[10])
        tx_errs = int(parts[11])
        tx_drop = int(parts[12])

        data: dict[str, Any] = {
            "interface": iface,
            "rx_bytes": rx_bytes, "tx_bytes": tx_bytes,
            "rx_packets": rx_packets, "tx_packets": tx_packets,
            "rx_errors": rx_errs, "tx_errors": tx_errs,
            "rx_dropped": rx_drop, "tx_dropped": tx_drop,
        }

        try:
            r = subprocess.run(["ip", "link", "show", iface],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and ("state UP" in r.stdout or ": UP" in r.stdout):
                data["up"] = True
                toks = r.stdout.split()
                for i, t in enumerate(toks):
                    if t == "link/ether" and i + 1 < len(toks):
                        data["mac"] = toks[i + 1]
                        break
            else:
                data["up"] = False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            data["up"] = None

        try:
            sp = Path(f"/sys/class/net/{iface}/speed")
            if sp.exists():
                data["speed_mbps"] = int(sp.read_text().strip())
        except Exception:
            pass

        try:
            mp = Path(f"/sys/class/net/{iface}/mtu")
            if mp.exists():
                data["mtu"] = int(mp.read_text().strip())
        except Exception:
            pass

        try:
            r = subprocess.run(["ip", "-4", "addr", "show", iface],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                data["ipv4"] = _parse_cidr_addrs(r.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        interfaces.append(data)

    # ── DNS check (via system resolver, handles systemd-resolved stub) ──
    dns_ok = False
    dns_latency_ms: float | None = None
    dns_server = "unknown"
    try:
        rc = Path("/etc/resolv.conf")
        if rc.exists():
            for dl in rc.read_text().splitlines():
                if dl.startswith("nameserver"):
                    dns_server = dl.split()[-1]
                    break

        # End-to-end resolution test using the OS resolver stack (systemd-resolved,
        # /etc/resolv.conf search domains, etc.) -- no raw socket hacks.
        start = time.monotonic()
        socket.getaddrinfo("example.com", 80, socket.AF_INET)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)

        dns_ok = True
        dns_latency_ms = elapsed_ms
    except Exception:
        dns_ok = False

    # ── Internet connectivity ──
    internet_ok: bool | None = None
    internet_ms: float | None = None
    target = "?"
    try:
        gw_out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5)
        default_gw = ""
        for line in gw_out.stdout.splitlines():
            if line.startswith("default"):
                toks = line.split()
                for i, t in enumerate(toks):
                    if t == "via" and i + 1 < len(toks):
                        default_gw = toks[i + 1]
                        break

        target = default_gw or "1.1.1.1"
        ping = subprocess.run(
            ["ping", "-c", "3", "-W", "2", target],
            capture_output=True, text=True, timeout=10,
        )
        for line in (ping.stdout + ping.stderr).splitlines():
            if "rtt" in line or "round-trip" in line:
                parts = line.split("/")
                if len(parts) >= 5:
                    try:
                        val_str = parts[4].strip().rstrip("ms")
                        internet_ms = round(float(val_str), 1)
                    except (ValueError, IndexError):
                        pass
        internet_ok = ping.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        internet_ok = None

    # ── Score ──
    issues: list[str] = []
    penalty = 0
    for p in interfaces:
        name = p["interface"]
        # Skip container/loopback interfaces from penalty (they are shown but not punished)
        if name == LOOPBACK or any(name.startswith(prefix) for prefix in CONTAINER_IFACE_PREFIXES):
            continue
        if not p.get("up"):
            issues.append(f"{name}: interface DOWN")
            penalty += 20
        if p.get("rx_errors", 0) or p.get("tx_errors", 0):
            issues.append(f"{name}: errors (RX={p['rx_errors']}, TX={p['tx_errors']})")
            penalty += 15
        if p.get("rx_dropped", 0) or p.get("tx_dropped", 0):
            issues.append(f"{name}: dropped packets (RX={p['rx_dropped']}, TX={p['tx_dropped']})")
            penalty += 15
    if not dns_ok:
        issues.append(f"DNS resolution failed ({dns_server})")
        penalty += 25
    if internet_ok is False:
        issues.append("Internet connectivity failure")
        penalty += 25

    score = max(0, round(100 - penalty, 1))

    return {
        "interfaces": interfaces,
        "dns": {"server": dns_server, "ok": dns_ok, "latency_ms": dns_latency_ms},
        "internet": {"reachable": internet_ok, "target": target, "rtt_ms": internet_ms},
        "issues": issues,
        "score": score,
    }


# ── Host metadata ───────────────────────────────────────────────────────

def host_info() -> dict[str, Any]:
    """Gather basic system identity information (read-only)."""
    info: dict[str, Any] = {}
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        info["hostname"] = "unknown"

    try:
        uptime_s = float(Path("/proc/uptime").read_text().split()[0])
        days, rem = divmod(int(uptime_s), 86400)
        hours, secs = divmod(rem, 3600)
        mins = secs // 60
        info["uptime"] = f"{days}d {hours}h {mins}m"
    except Exception:
        info["uptime"] = "unknown"

    try:
        info["kernel"] = os.uname().release
    except Exception:
        info["kernel"] = "unknown"

    try:
        distro = Path("/etc/os-release")
        if distro.exists():
            for line in distro.read_text().splitlines():
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip('"')
                    break
    except Exception:
        pass

    try:
        info["local_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass

    return info


# ── Report formatting ───────────────────────────────────────────────────

def _fmt_num(n: Any) -> str:
    if isinstance(n, float):
        return f"{n:.1f}"
    return str(n)


def format_report(data: dict[str, Any]) -> str:
    """Build a human-readable report from collected health data."""
    lines: list[str] = []
    sep = "=" * 72

    lines.append(sep)
    lines.append(f"  SYSTEM HEALTH DIAGNOSTIC -- {data['host'].get('local_time', '?')}")
    lines.append(sep)
    lines.append("")

    h = data["host"]
    lines.append(f"  Hostname : {h.get('hostname', '?')}")
    lines.append(f"  OS       : {h.get('os', '?')}")
    lines.append(f"  Kernel   : {h.get('kernel', '?')}")
    lines.append(f"  Uptime   : {h.get('uptime', '?')}")
    lines.append("")

    cats = data["categories"]
    non_none_scores = [c["score"] for c in cats.values() if c["score"] is not None]
    overall = round(sum(non_none_scores) / len(non_none_scores), 1) if non_none_scores else 0
    box_w = 68
    lines.append(f"  +{'-' * box_w}+")
    tag_plain = _status(overall)
    plain_tag = "".join(c for c in tag_plain if c not in "\033[]B")
    prefix = "OVERALL HEALTH SCORE: "
    suffix = f"{overall}/100"
    content_len = 2 + len(prefix) + len(plain_tag) + 1 + len(suffix)
    pad = box_w - (content_len - 2)
    lines.append(f"  | {prefix}{tag_plain} {suffix}" + " " * max(pad, 0) + "|")
    lines.append(f"  +{'-' * box_w}+")
    lines.append("")

    for name, cat in cats.items():
        score = cat.get("score")
        tag = _status(score, high_is_bad=False) if score is not None else "N/A"
        display = cat.get("score_display", "")
        lines.append(f"  [{tag}] {name.upper()} -- {display}")

        detail = cat.get("data", {})
        if isinstance(detail, dict):
            for k, v in detail.items():
                label = k.replace("_", " ").title()
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    lines.append(f"      {label}:")
                    for item in v:
                        pairs = ", ".join(f"{ik}={_human_bytes(iv * 1073741824) if ik.endswith("_gb") else _fmt_num(iv)}" for ik, iv in item.items())
                        lines.append(f"        - {pairs}")
                elif isinstance(v, list):
                    lines.append(f"      {label}: {_fmt_num(v[0])}" if len(v) == 1 else f"      {label}:")
                    for item in v:
                        lines.append(f"        - {item}")
                elif isinstance(v, dict):
                    lines.append(f"      {label}:")
                    for ik, iv in v.items():
                        ilabel = ik.replace("_", " ").title()
                        if isinstance(iv, dict):
                            lines.append(f"        {ilabel}:")
                            for ik2, iv2 in iv.items():
                                lines.append(f"          {ik2.replace('_', ' ').title()}: {_fmt_num(iv2)}")
                        else:
                            lines.append(f"        {ilabel}: {_fmt_num(iv)}")
                else:
                    lines.append(f"      {label}: {_fmt_num(v)}")

        if cat.get("issues"):
            lines.append("      Issues:")
            for iss in cat["issues"]:
                lines.append(f"        [!] {iss}")

        lines.append("")

    return "\n".join(lines)


# ── Main ────────────────────────────────────────────────────────────────

def collect(interval: float = 1.0) -> dict[str, Any]:
    """Run all health checks and return a structured report."""
    categories: dict[str, dict] = {}

    # CPU
    cpu = cpu_health(interval)
    categories["CPU"] = {
        "score": cpu["score"],
        "score_display": f"{cpu['percent']}% util, load {cpu['load_average']['1m']}/{cpu['logical_cpus']} cores",
        "issues": [] if (cpu["score"] is None or cpu["score"] >= 25) else ["High CPU utilisation"],
        "data": {
            "utilisation_percent": cpu["percent"],
            "load_average": cpu["load_average"],
            "logical_cpus": cpu["logical_cpus"],
            "frequency": cpu.get("frequency_ghz"),
            "cores": cpu.get("cores", []),
        },
    }

    # Memory
    mem = memory_health()
    categories["Memory"] = {
        "score": mem["score"],
        "score_display": f"{mem['used_percent']}% used ({_human_bytes(mem['used_gb'] * 1073741824)}/{_human_bytes(mem['total_gb'] * 1073741824)})", 
        "issues": [],
        "data": {k: v for k, v in mem.items() if k != "score"},
    }

    # Temperature
    temp = temperature_health()
    if temp.get("error"):
        categories["Temperature"] = {
            "score": None,
            "score_display": f"n/a ({temp['error']})",
            "issues": [],
            "data": {"error": temp["error"]},
        }
    else:
        zone_strs = [f"{z['label']}={z['celsius']}" for z in temp["zones"]]
        max_t = max(z["celsius"] for z in temp["zones"])
        categories["Temperature"] = {
            "score": temp["score"],
            "score_display": f"max {max_t} C -- {', '.join(zone_strs)}",
            "issues": [],
            "data": temp["zones"],
        }

    # Disk
    disk = disk_health(interval)
    part_strs = [f"{p['mountpoint']}={p['used_percent']}% ({_human_bytes(p['used_gb'] * 1073741824)}/{_human_bytes(p['total_gb'] * 1073741824)})" 
                 for p in disk["partitions"]]
    categories["Disk"] = {
        "score": disk["score"],
        "score_display": ", ".join(part_strs) if part_strs else "No partitions found",
        "issues": [],
        "data": {
            "partitions": disk["partitions"],
            "total_reads": disk.get("io_total", {}).get("reads"),
            "total_writes": disk.get("io_total", {}).get("writes"),
            "overall_disk_busy_percent": disk.get("overall_disk_busy_percent"),
        },
    }

    # Network
    net = network_health()
    iface_strs = [f"{p['interface']}" + (" UP" if p.get("up") else " DOWN") for p in net["interfaces"]]
    net_issues: list[str] = []
    for p in net["interfaces"]:
        name = p["interface"]
        # Skip container/loopback interfaces from issues display
        if name == LOOPBACK or any(name.startswith(prefix) for prefix in CONTAINER_IFACE_PREFIXES):
            continue
        if not p.get("up"):
            net_issues.append(f"{name}: DOWN")
        if p.get("rx_errors", 0) or p.get("tx_errors", 0):
            net_issues.append(f"{name}: errors (RX={p['rx_errors']}, TX={p['tx_errors']})")
        if p.get("rx_dropped", 0) or p.get("tx_dropped", 0):
            net_issues.append(f"{name}: dropped packets")
    if not net.get("dns", {}).get("ok"):
        net_issues.append("DNS resolution failed")
    if net.get("internet", {}).get("reachable") is False:
        net_issues.append("Internet connectivity failure")

    categories["Network"] = {
        "score": net["score"],
        "score_display": "; ".join(iface_strs) if iface_strs else "No interfaces found",
        "issues": net_issues,
        "data": {
            "interfaces": net["interfaces"],
            "dns": net.get("dns"),
            "internet": net.get("internet"),
        },
    }

    return {
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "host": host_info(),
        "categories": categories,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ubuntu 24.04 System Health Diagnostic (read-only)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format instead of human-readable table",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds for CPU/disk measurement windows (default: 1.0)",
    )
    args = parser.parse_args()

    report = collect(args.interval)

    if args.json:
        def _clean(o: Any) -> Any:
            if isinstance(o, dict):
                return {k: _clean(v) for k, v in o.items()}
            if isinstance(o, list):
                return [_clean(i) for i in o]
            if isinstance(o, tuple):
                return [i for i in o]
            if isinstance(o, bytes):
                return None
            return o

        print(json.dumps(_clean(report), indent=2))
    else:
        print(format_report(report))


if __name__ == "__main__":
    main()
