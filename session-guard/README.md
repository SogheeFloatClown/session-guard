# session-guard

A local privacy-session monitor. During a session it:

1. Baselines running processes and periodically scans for keylogger / screen-capture indicators (heuristic).
2. Tracks every file created or modified under watched folders.
3. At the end, securely overwrites and deletes files **created** during the session (existing files that were modified are reported, never wiped).

## Usage

    pip install -r requirements.txt
    python session_guard.py --watch ~/Downloads ~/Documents --interval 10

Ctrl+C ends the session and prompts before wiping. Run as root/admin for fuller process visibility.

## Limitations

- Detection is heuristic, not antivirus; kernel-level malware will not be seen.
- Overwriting is unreliable on SSDs, journaling/copy-on-write filesystems (APFS, btrfs, ZFS, NTFS) and synced folders. For real protection, keep session data in an encrypted volume or tmpfs and destroy the key.
- This tool runs on your own machine. It is not meant to run in GitHub Actions (runners are ephemeral); Actions is only used here for tests.

## Development

    pip install pytest && python -m pytest

MIT licensed.
