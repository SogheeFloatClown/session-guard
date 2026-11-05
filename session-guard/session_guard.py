#!/usr/bin/env python3
"""
session_guard.py - privacy session monitor

What it does
  1. Baselines running processes at session start.
  2. Periodically scans for keylogger / screen-capture indicators (heuristic).
  3. Tracks every file CREATED or MODIFIED under watched folders.
  4. At session end, shows a summary and (after confirmation) securely
     overwrites + deletes files CREATED during the session.
     Files that already existed and were modified are only reported,
     never wiped (that would destroy your own data).

Install:  pip install psutil watchdog
Run:      python session_guard.py --watch ~/Downloads ~/Documents --interval 10
Stop:     Ctrl+C (or --duration SECONDS)

LIMITS (read these):
  - Detection is heuristic, not antivirus. Kernel-level or well-hidden
    malware will not be seen. Treat alerts as leads, not verdicts.
  - Overwriting does NOT reliably erase data on SSDs (wear leveling),
    journaling or copy-on-write filesystems (APFS, btrfs, ZFS, NTFS
    shadow copies), or cloud-synced folders. For real protection, keep
    session data inside an encrypted volume or tmpfs and destroy the key.
"""
import argparse
import json
import os
import secrets
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Names commonly tied to keylogging, screen capture or remote viewing.
# Some are legitimate tools; hits are "review", not "malware".
SUSPECT_NAMES = {
    "logkeys", "keylogger", "pykeylogger", "lkl", "kidlogger", "ardamax",
    "x11vnc", "vncserver", "tigervnc", "teamviewer", "anydesk", "rustdesk",
    "scrot", "grim", "wf-recorder", "simplescreenrecorder", "kazam",
    "obs", "obs64", "ffmpeg", "xev", "xinput",
}

LOG_PATH = Path(tempfile.gettempdir()) / "session_guard_alerts.jsonl"


def now():
    return time.strftime("%H:%M:%S")


def alert(kind, detail):
    entry = {"t": time.time(), "kind": kind, "detail": detail}
    print(f"[{now()}] ALERT {kind}: {detail}")
    try:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- processes
class ProcessMonitor(threading.Thread):
    def __init__(self, interval):
        super().__init__(daemon=True)
        self.interval = interval
        self.stop_evt = threading.Event()
        self.baseline = self._snapshot()
        self.flagged = set()

    @staticmethod
    def _snapshot():
        snap = set()
        for p in psutil.process_iter(["pid", "name", "create_time"]):
            snap.add((p.info["pid"], p.info["create_time"]))
        return snap

    def _check(self, proc):
        try:
            name = (proc.info["name"] or "").lower().removesuffix(".exe")
            key = (proc.info["pid"], proc.info["create_time"])
            if key in self.flagged:
                return
            reasons = []
            if name in SUSPECT_NAMES:
                reasons.append("name matches capture/logging tool list")
            # Linux: raw keyboard device handles are a classic keylogger tell.
            # (Needs root to see other users' processes.)
            try:
                for f in proc.open_files():
                    if f.path.startswith("/dev/input/event"):
                        reasons.append(f"holds raw input device {f.path}")
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            # New process started mid-session and talking to the network
            # while having no visible window/terminal is worth a look.
            if key not in self.baseline:
                try:
                    conns = proc.net_connections(kind="inet")
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    conns = []
                remote = [c for c in conns if c.raddr]
                if remote and not proc.terminal():
                    reasons.append(
                        f"new background process with {len(remote)} remote connection(s)"
                    )
            if reasons:
                self.flagged.add(key)
                alert("process", f"{name} (pid {proc.info['pid']}): " + "; ".join(reasons))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def run(self):
        while not self.stop_evt.is_set():
            for p in psutil.process_iter(["pid", "name", "create_time"]):
                self._check(p)
            self.stop_evt.wait(self.interval)


# --------------------------------------------------------------- file writes
class WriteTracker(FileSystemEventHandler):
    def __init__(self, excludes):
        self.created = set()
        self.modified_existing = set()
        self.excludes = [str(Path(e).resolve()) for e in excludes] + [str(LOG_PATH)]
        self.lock = threading.Lock()

    def _skip(self, path):
        return any(path.startswith(e) for e in self.excludes)

    def on_created(self, event):
        if event.is_directory or self._skip(event.src_path):
            return
        with self.lock:
            self.created.add(event.src_path)

    def on_moved(self, event):
        if event.is_directory or self._skip(event.dest_path):
            return
        with self.lock:
            if event.src_path in self.created:
                self.created.discard(event.src_path)
                self.created.add(event.dest_path)
            else:
                self.created.add(event.dest_path)

    def on_modified(self, event):
        if event.is_directory or self._skip(event.src_path):
            return
        with self.lock:
            if event.src_path not in self.created:
                self.modified_existing.add(event.src_path)


# -------------------------------------------------------------------- wiping
def secure_overwrite(path, passes=1):
    """Overwrite file contents with random bytes, then truncate and delete."""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        return False
    try:
        size = p.stat().st_size
        with open(p, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    n = min(1 << 20, remaining)
                    f.write(secrets.token_bytes(n))
                    remaining -= n
                f.flush()
                os.fsync(f.fileno())
            f.truncate(0)
        p.unlink()
        return True
    except OSError as e:
        print(f"  could not wipe {path}: {e}")
        return False


# ---------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="Session monitor + end-of-session wipe")
    ap.add_argument("--watch", nargs="+", default=[str(Path.home()), tempfile.gettempdir()],
                    help="folders to track (default: home + temp)")
    ap.add_argument("--exclude", nargs="*", default=[], help="paths to ignore")
    ap.add_argument("--interval", type=int, default=10, help="process scan seconds")
    ap.add_argument("--duration", type=int, default=0, help="auto-end after N seconds")
    ap.add_argument("--passes", type=int, default=3, help="overwrite passes")
    ap.add_argument("--yes", action="store_true", help="wipe without confirmation prompt")
    args = ap.parse_args()

    tracker = WriteTracker(args.exclude)
    observer = Observer()
    for w in args.watch:
        if Path(w).exists():
            observer.schedule(tracker, w, recursive=True)
            print(f"watching {w}")
    observer.start()

    monitor = ProcessMonitor(args.interval)
    monitor.start()
    print(f"[{now()}] session started. Ctrl+C to end. Alerts also logged to {LOG_PATH}")

    done = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: done.set())
    signal.signal(signal.SIGTERM, lambda *_: done.set())
    done.wait(args.duration or None)

    monitor.stop_evt.set()
    observer.stop()
    observer.join()

    created = sorted(p for p in tracker.created if os.path.isfile(p))
    print(f"\n=== session summary ===")
    print(f"process alerts : {len(monitor.flagged)}")
    print(f"files created  : {len(created)}")
    print(f"existing files modified (will NOT be wiped): {len(tracker.modified_existing)}")
    for p in sorted(tracker.modified_existing)[:25]:
        print(f"  modified: {p}")

    if not created:
        return
    for p in created[:25]:
        print(f"  created : {p}")
    if len(created) > 25:
        print(f"  ... and {len(created) - 25} more")

    if not args.yes:
        if input("\nOverwrite and delete the files created this session? [y/N] ").lower() != "y":
            print("nothing wiped.")
            return
    wiped = sum(secure_overwrite(p, args.passes) for p in created)
    print(f"wiped {wiped}/{len(created)} files.")


if __name__ == "__main__":
    sys.exit(main())
