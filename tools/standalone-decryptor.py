#!/usr/bin/env python3
"""
MySecret Standalone Vault Decryptor (Zero-Dependency Python Recovery Tool)
-------------------------------------------------------------------------
This script allows you to recover and decrypt your Obsidian notes and attachments
WITHOUT depending on the MySecret plugin or Obsidian itself.

Requirements:
    pip install cryptography argon2-cffi

Usage:
    # 1. Decrypt using your 24-word BIP-39 recovery phrase:
    python standalone-decryptor.py --vault /path/to/vault --mnemonic "word1 word2 ... word24" --output /path/to/decrypted_vault

    # 2. Decrypt using your Master Password and data.json:
    python standalone-decryptor.py --vault /path/to/vault --password "MyMasterPassword" --output /path/to/decrypted_vault

    # 3. Decrypt a single file:
    python standalone-decryptor.py --file /path/to/note.md --relative-path "Notes/note.md" --mnemonic "word1 ... word24"
"""

import os
import sys
import json
import base64
import unicodedata
import argparse
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: Missing required library 'cryptography'.")
    print("Install it with: pip install cryptography argon2-cffi")
    sys.exit(1)

ARMORED_START = "-----BEGIN MYSECRET ENCRYPTED FILE-----"
ARMORED_END = "-----END MYSECRET ENCRYPTED FILE-----"
BINARY_MAGIC = b"MYSE"


def derive_key_from_bip39(mnemonic: str, passphrase: str = "") -> bytes:
    """Derives the 32-byte vault key from a 24-word BIP-39 mnemonic phrase."""
    mnemonic_clean = unicodedata.normalize("NFKD", mnemonic.strip().lower())
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode("utf-8")
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=2048
    )
    return kdf.derive(mnemonic_clean.encode("utf-8"))


def derive_key_from_password(password: str, data_json_path: str) -> bytes:
    """Derives the vault key from master password and data.json envelope."""
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        print("Error: 'argon2-cffi' is required to decrypt with master password.")
        print("Install it with: pip install argon2-cffi")
        sys.exit(1)

    with open(data_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    envelope = data.get("vaultEnvelope")
    if not envelope:
        raise ValueError("Invalid data.json: missing 'vaultEnvelope'")

    salt = base64.b64decode(envelope["salt"])
    iterations = envelope.get("iterations", 3)
    memory_kib = envelope.get("memoryKib", 65536)
    parallelism = envelope.get("parallelism", 1)

    master_key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID
    )

    # Unwrap vaultKey
    wrapped_key_b64 = envelope["wrappedVaultKey"]
    wrapped_data = base64.b64decode(wrapped_key_b64)
    iv = wrapped_data[:12]
    tag = wrapped_data[12:28]
    ciphertext = wrapped_data[28:]

    aesgcm = AESGCM(master_key)
    aad = b"mysecret-vault-envelope-v1"
    vault_key = aesgcm.decrypt(iv, ciphertext + tag, aad)
    return vault_key


def decrypt_text_armored(armored_text: str, relative_path: str, vault_key: bytes) -> str:
    """Decrypts an ASCII-armored Markdown file."""
    start_idx = armored_text.find(ARMORED_START)
    end_idx = armored_text.find(ARMORED_END)
    if start_idx == -1 or end_idx == -1:
        raise ValueError("Not a valid armored MySecret file.")

    content = armored_text[start_idx + len(ARMORED_START):end_idx].strip()
    lines = content.splitlines()

    iv_b64 = ""
    tag_b64 = ""
    cipher_lines = []

    header_mode = True
    for line in lines:
        line_str = line.strip()
        if header_mode:
            if line_str == "":
                header_mode = False
                continue
            if line_str.startswith("IV:"):
                iv_b64 = line_str.split(":", 1)[1].strip()
            elif line_str.startswith("Tag:"):
                tag_b64 = line_str.split(":", 1)[1].strip()
        else:
            if line_str:
                cipher_lines.append(line_str)

    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode("".join(cipher_lines))

    # AAD is the NFC-normalized relative path with forward slashes
    norm_path = unicodedata.normalize("NFC", relative_path.replace("\\", "/"))
    aad = norm_path.encode("utf-8")

    aesgcm = AESGCM(vault_key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext + tag, aad)
    return plaintext_bytes.decode("utf-8")


def decrypt_binary_attachment(raw_bytes: bytes, relative_path: str, vault_key: bytes) -> bytes:
    """Decrypts a binary attachment (images, audio, PDFs)."""
    if not raw_bytes.startswith(BINARY_MAGIC):
        return raw_bytes  # Already plaintext

    version = raw_bytes[4]
    iv = raw_bytes[5:17]
    tag = raw_bytes[17:33]
    ciphertext = raw_bytes[33:]

    norm_path = unicodedata.normalize("NFC", relative_path.replace("\\", "/"))
    aad = norm_path.encode("utf-8")

    aesgcm = AESGCM(vault_key)
    return aesgcm.decrypt(iv, ciphertext + tag, aad)


def process_vault(vault_dir: Path, output_dir: Path, vault_key: bytes):
    """Batch decrypts an entire Obsidian vault into plaintext."""
    print(f"\n[+] Starting vault decryption: {vault_dir} -> {output_dir}")
    processed = 0
    skipped = 0

    for root, dirs, files in os.walk(vault_dir):
        # Exclude hidden system and git directories
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for file_name in files:
            full_path = Path(root) / file_name
            rel_path = full_path.relative_to(vault_dir).as_posix()
            out_file = output_dir / rel_path

            out_file.parent.mkdir(parents=True, exist_ok=True)

            try:
                if file_name.endswith((".md", ".canvas", ".txt")):
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        text = f.read()
                    if ARMORED_START in text:
                        decrypted = decrypt_text_armored(text, rel_path, vault_key)
                        with open(out_file, "w", encoding="utf-8") as f:
                            f.write(decrypted)
                        processed += 1
                    else:
                        out_file.write_text(text, encoding="utf-8")
                        skipped += 1
                else:
                    # Binary attachment
                    with open(full_path, "rb") as f:
                        raw = f.read()
                    if raw.startswith(BINARY_MAGIC):
                        decrypted = decrypt_binary_attachment(raw, rel_path, vault_key)
                        with open(out_file, "wb") as f:
                            f.write(decrypted)
                        processed += 1
                    else:
                        out_file.write_bytes(raw)
                        skipped += 1
            except Exception as e:
                print(f"[-] Error decrypting {rel_path}: {e}")

    print(f"\n[✓] Decryption complete!")
    print(f"    - Decrypted files: {processed}")
    print(f"    - Unmodified plaintext files: {skipped}")
    print(f"    - Destination: {output_dir}\n")


def main():
    parser = argparse.ArgumentParser(description="MySecret Standalone Vault Decryptor")
    parser.add_argument("--vault", type=str, help="Path to your Obsidian vault directory")
    parser.add_argument("--output", type=str, help="Destination directory for decrypted files")
    parser.add_argument("--mnemonic", type=str, help="24-word BIP-39 recovery phrase")
    parser.add_argument("--password", type=str, help="Vault master password")
    parser.add_argument("--data-json", type=str, help="Path to data.json (required if using --password)")
    parser.add_argument("--file", type=str, help="Single file to decrypt")
    parser.add_argument("--relative-path", type=str, help="Vault relative path of the single file")

    args = parser.parse_args()

    if not args.mnemonic and not args.password:
        parser.error("You must provide either --mnemonic (24 words) or --password.")

    # 1. Derive key
    if args.mnemonic:
        print("[*] Deriving vault key from 24-word BIP-39 mnemonic...")
        vault_key = derive_key_from_bip39(args.mnemonic)
    else:
        data_json = args.data_json
        if not data_json and args.vault:
            candidate = Path(args.vault) / ".obsidian" / "plugins" / "mysecret" / "data.json"
            if candidate.exists():
                data_json = str(candidate)
        if not data_json or not os.path.exists(data_json):
            parser.error("Could not find data.json. Specify it with --data-json.")
        print("[*] Deriving vault key from master password and data.json via Argon2id...")
        vault_key = derive_key_from_password(args.password, data_json)

    print("[+] Key derived successfully!")

    # 2. Execute
    if args.file:
        rel = args.relative_path or os.path.basename(args.file)
        with open(args.file, "r", encoding="utf-8") as f:
            content = f.read()
        print(f"\n--- Decrypted Content ({rel}) ---")
        print(decrypt_text_armored(content, rel, vault_key))
    elif args.vault:
        if not args.output:
            parser.error("--output directory is required when decrypting a vault.")
        process_vault(Path(args.vault), Path(args.output), vault_key)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
