#!/usr/bin/env python3
import argparse
import json
import os


def _load_report(path):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # .ips files often contain two JSON objects concatenated by newline.
        lines = text.splitlines()
        if len(lines) < 2:
            raise
        header = json.loads(lines[0])
        body = json.loads("\n".join(lines[1:]))
        if isinstance(body, dict) and isinstance(header, dict):
            merged = dict(body)
            for key, value in header.items():
                merged.setdefault(key, value)
            return merged
        return body


def _find_latest_report(reports_dir):
    if not os.path.isdir(reports_dir):
        return None
    candidates = []
    for name in os.listdir(reports_dir):
        if name.startswith("binaryninja-") and name.endswith(".ips"):
            path = os.path.join(reports_dir, name)
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            candidates.append((mtime, path))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def _fmt_timestamp(value):
    if not value:
        return "unknown"
    return value


def _get_exception(data):
    exc = data.get("exception", {}) if isinstance(data, dict) else {}
    return {
        "type": exc.get("type", "unknown"),
        "signal": exc.get("signal", "unknown"),
        "subtype": exc.get("subtype", "unknown"),
        "codes": exc.get("codes", "unknown"),
    }


def _find_triggered_thread(data):
    threads = data.get("threads", []) if isinstance(data, dict) else []
    for thread in threads:
        if thread.get("triggered"):
            return thread
    return threads[0] if threads else None


def _get_image_map(data):
    image_map = {}
    for img in data.get("usedImages", []) if isinstance(data, dict) else []:
        name = img.get("name") or img.get("path")
        if not name:
            continue
        image_map[img.get("imageIndex")] = name
    return image_map


def _print_header(data, path):
    print("Crash report:", path)
    print("App:", data.get("app_name", "unknown"))
    print("Version:", data.get("app_version", "unknown"))
    print("Timestamp:", _fmt_timestamp(data.get("timestamp")))


def _print_exception(data):
    exc = _get_exception(data)
    print("Exception:", exc["type"])
    print("Signal:", exc["signal"])
    print("Subtype:", exc["subtype"])
    print("Codes:", exc["codes"])


def _print_triggered_thread(data, max_frames):
    thread = _find_triggered_thread(data)
    if not thread:
        print("No thread data found.")
        return
    print("Triggered thread id:", thread.get("id", "unknown"))
    if "queue" in thread:
        print("Queue:", thread.get("queue"))

    image_map = _get_image_map(data)
    frames = thread.get("frames", [])
    print("Top frames:")
    limit = len(frames) if max_frames <= 0 else min(max_frames, len(frames))
    for frame in frames[:limit]:
        image = image_map.get(frame.get("imageIndex"), "unknown")
        symbol = frame.get("symbol")
        offset = frame.get("imageOffset")
        location = ""
        if symbol:
            location = symbol
            sym_loc = frame.get("symbolLocation")
            if sym_loc is not None:
                location = f"{symbol}+{sym_loc}"
        print(f"- {image} @ {offset} {location}")


def _print_plugin_presence(data, needle):
    found = False
    for img in data.get("usedImages", []) if isinstance(data, dict) else []:
        path = img.get("path", "")
        if needle in path:
            found = True
            print("Plugin image:", path)
            print("Plugin uuid:", img.get("uuid", "unknown"))
            print("Plugin base:", img.get("base", "unknown"))
            print("Plugin size:", img.get("size", "unknown"))
            break
    if not found:
        print("Plugin image not found:", needle)


def _read_log_lines(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()
    except OSError:
        return []


def _print_log_snippets(log_path, patterns, max_lines, context_lines):
    if not log_path:
        return
    lines = _read_log_lines(log_path)
    if not lines:
        print("Log:", log_path, "(not found or empty)")
        return

    hits = []
    for idx, line in enumerate(lines):
        for pat in patterns:
            if pat in line:
                hits.append(idx)
                break

    if not hits:
        print("Log:", log_path, "(no matches)")
        return

    print("Log:", log_path)
    if max_lines > 0:
        hits = hits[-max_lines:]
    for idx in hits:
        start = max(0, idx - context_lines)
        end = min(len(lines), idx + context_lines + 1)
        for line in lines[start:end]:
            print("-", line.rstrip("\n"))
        if end < len(lines):
            print("- ---")


def main():
    parser = argparse.ArgumentParser(description="Summarize Binary Ninja crash reports.")
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to a .ips crash report. Defaults to newest in CrashReports.",
    )
    parser.add_argument(
        "--reports-dir",
        default=os.path.join(os.getcwd(), "CrashReports"),
        help="Directory with crash reports (default: ./CrashReports).",
    )
    parser.add_argument(
        "--plugin",
        default="libarch_armv5.dylib",
        help="Plugin library name to search for.",
    )
    parser.add_argument(
        "--log",
        default=os.path.join(os.getcwd(), "bnlog.log"),
        help="Binary Ninja log file to scan (default: ./bnlog.log).",
    )
    parser.add_argument(
        "--log-lines",
        type=int,
        default=80,
        help="Max log matches to print (default: 80).",
    )
    parser.add_argument(
        "--log-context",
        type=int,
        default=0,
        help="Context lines before/after each log match (default: 0).",
    )
    parser.add_argument(
        "--stack-frames",
        type=int,
        default=20,
        help="Max triggered thread frames to print (0=all).",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Write summary JSON to this path if set.",
    )
    args = parser.parse_args()

    path = args.path or _find_latest_report(args.reports_dir)
    if not path:
        print("No crash report found.")
        return 1

    data = _load_report(path)
    if not isinstance(data, dict):
        print("Crash report is not a JSON object.")
        return 1

    _print_header(data, path)
    _print_exception(data)
    _print_triggered_thread(data, args.stack_frames)
    _print_plugin_presence(data, args.plugin)
    _print_log_snippets(
        args.log,
        patterns=[
            "ARMv5",
            "Firmware workflow scan",
            "Firmware scan plan",
            "Firmware scan:",
            "RunArmv5FirmwareWorkflow",
        ],
        max_lines=args.log_lines,
        context_lines=args.log_context,
    )

    if args.json_out:
        thread = _find_triggered_thread(data)
        summary = {
            "path": path,
            "app": data.get("app_name", "unknown"),
            "version": data.get("app_version", "unknown"),
            "timestamp": data.get("timestamp"),
            "exception": _get_exception(data),
            "triggered_thread": {
                "id": thread.get("id") if thread else None,
                "queue": thread.get("queue") if thread else None,
                "frames": (thread.get("frames") if thread else None),
            },
        }
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
