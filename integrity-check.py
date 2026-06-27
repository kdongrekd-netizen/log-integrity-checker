#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path

# Secure location to store the reference hashes
HASH_STORE_FILE = Path.home() / ".log_integrity_hashes.json"


def calculate_sha256(file_path: Path) -> str:
    """Computes the SHA-256 hash of a file efficiently by chunking."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read in 4KB chunks to handle large log files smoothly
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError:
        print(f"Error: Permission denied reading {file_path}")
        return ""
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ""


def load_stored_hashes() -> dict:
    """Loads the database of previously computed hashes."""
    if not HASH_STORE_FILE.exists():
        return {}
    try:
        with open(HASH_STORE_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading hash database: {e}")
        return {}


def save_hashes(hashes: dict):
    """Saves the database of hashes securely."""
    try:
        # Create parent directories if they don't exist
        HASH_STORE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(HASH_STORE_FILE, "w") as f:
            json.dump(hashes, f, indent=4)
    except Exception as e:
        print(f"Error saving hash database: {e}")


def get_target_files(target_path: Path) -> list[Path]:
    """Expands a directory into individual files, or returns a list containing the single file."""
    if not target_path.exists():
        print(f"Error: Path '{target_path}' does not exist.")
        return []

    if target_path.is_file():
        return [target_path]
    elif target_path.is_dir():
        # Recursively find all files in the directory
        return [p for p in target_path.rgid("*") if p.is_file()] if hasattr(target_path, 'rglob') else [
            Path(root) / f for root, _, files in os.walk(target_path) for f in files
        ]
    return []


def handle_init(target_path: Path):
    """Initializes/stores hashes for the specified files."""
    files = get_target_files(target_path)
    if not files:
        return

    stored_hashes = load_stored_hashes()
    for file in files:
        resolved_path = str(file.resolve())
        file_hash = calculate_sha256(file)
        if file_hash:
            stored_hashes[resolved_path] = file_hash

    save_hashes(stored_hashes)
    print("Hashes stored successfully.")


def handle_check(target_path: Path):
    """Compares current hashes against stored records to detect modifications or tampering."""
    files = get_target_files(target_path)
    if not files:
        return

    stored_hashes = load_stored_hashes()
    if not stored_hashes:
        print("Error: No integrity database found. Please run 'init' first.")
        return

    for file in files:
        resolved_path = str(file.resolve())
        if resolved_path not in stored_hashes:
            print(f"File: {file} -> Status: UNTRACKED (No baseline hash recorded)")
            continue

        current_hash = calculate_sha256(file)
        if not current_hash:
            continue

        if current_hash == stored_hashes[resolved_path]:
            print(f"File: {file} -> Status: Unmodified")
        else:
            print(f"File: {file} -> Status: MODIFIED (Hash mismatch! Potential Tampering)")


def handle_update(target_path: Path):
    """Updates/re-initializes the hash for a specific file or directory after a known, authorized change."""
    files = get_target_files(target_path)
    if not files:
        return

    stored_hashes = load_stored_hashes()
    for file in files:
        resolved_path = str(file.resolve())
        file_hash = calculate_sha256(file)
        if file_hash:
            stored_hashes[resolved_path] = file_hash

    save_hashes(stored_hashes)
    print("Hash(es) updated successfully.")


def main():
    parser = argparse.ArgumentParser(
        description="Log File Integrity Monitor using SHA-256."
    )
    parser.add_argument(
        "action",
        choices=["init", "check", "update"],
        help="Action to perform: 'init' to baseline, 'check' to verify, 'update' to re-initialize authorized changes.",
    )
    parser.add_argument(
        "path", help="The target file or directory path to process."
    )

    args = parser.parse_args()
    target_path = Path(args.path)

    if args.action == "init":
        handle_init(target_path)
    elif args.action == "check":
        handle_check(target_path)
    elif args.action == "update":
        handle_update(target_path)


if __name__ == "__main__":
    main()