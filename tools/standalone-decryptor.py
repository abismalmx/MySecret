#!/usr/bin/env python3
"""
MySecret Standalone Vault Decryptor (recovery tool, works WITHOUT Obsidian)
--------------------------------------------------------------------------
Decrypts notes and attachments produced by the MySecret plugin using only
what is stored in the vault plus your master password or your 24-word
recovery phrase.

It implements the REAL on-disk format of the plugin (see SECURITY.md):

  vault-envelope.json  (.obsidian/plugins/mysecret/vault-envelope.json)
      argon2{memory,iterations,parallelism,salt}   hex
      vaultKeyEnvelope{iv,tag,ciphertext}          hex   AES-GCM, AAD "vault-envelope"
      recoveryEnvelope{salt,iv,tag,ciphertext}     hex   AES-GCM, AAD "recovery-envelope"

  master password --Argon2id(salt)--------------> passKey ----+
                                                               +--> unwraps the 32-byte VAULT KEY
  24 words --PBKDF2-HMAC-SHA512(2048, recSalt)--> recoveryKey -+

  notes (.md/.canvas/.txt)  armored text, AES-256-GCM, AAD = NFC vault path
  attachments               "MYSE" | ver | iv(12) | tag(16) | ciphertext

Requirements (NOT stdlib-only: AES-GCM and Argon2id are not in the stdlib):
    pip install cryptography            # always
    pip install argon2-cffi             # only for --password

Usage:
    # whole vault, using the recovery phrase
    python standalone-decryptor.py --vault /path/to/vault --mnemonic "w1 w2 ... w24" --output /path/to/out

    # whole vault, using the master password (prompts if --password is omitted)
    python standalone-decryptor.py --vault /path/to/vault --password --output /path/to/out

    # a single file
    python standalone-decryptor.py --envelope vault-envelope.json --mnemonic "..." \\
        --file note.md --relative-path "Notes/note.md"
"""

import argparse
import base64
import getpass
import json
import os
import sys
import unicodedata
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("Error: the 'cryptography' package is required.\n  pip install cryptography")
    sys.exit(1)

ARMORED_START = b"-----BEGIN MYSECRET ENCRYPTED FILE-----"
ARMORED_END = b"-----END MYSECRET ENCRYPTED FILE-----"
BINARY_MAGIC = b"MYSE"
BINARY_HEADER_LENGTH = 33  # 4 magic + 1 version + 12 iv + 16 tag
TEXT_EXTENSIONS = (".md", ".canvas", ".txt")

# Same bounds the plugin enforces (src/constants.ts): the envelope is untrusted.
MIN_MEMORY_KIB, MAX_MEMORY_KIB = 65536, 1048576
MIN_ITERATIONS, MAX_ITERATIONS = 3, 20
MIN_PARALLELISM, MAX_PARALLELISM = 1, 16


class DecryptError(Exception):
    pass


# ---------------------------------------------------------------------------
# Envelope / key unwrapping
# ---------------------------------------------------------------------------

def find_envelope(vault: Path, explicit: str = None) -> Path:
    if explicit:
        return Path(explicit)
    for candidate in (
        vault / ".obsidian" / "plugins" / "mysecret" / "vault-envelope.json",
        vault / "vault-envelope.json",
    ):
        if candidate.is_file():
            return candidate
    raise DecryptError(
        "vault-envelope.json not found. Pass it explicitly with --envelope "
        "(it lives in .obsidian/plugins/mysecret/)."
    )


def load_envelope(path: Path) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            envelope = json.load(f)
    except (OSError, ValueError) as exc:
        raise DecryptError(f"Cannot read {path}: {exc}")
    if not isinstance(envelope, dict) or "vaultKeyEnvelope" not in envelope or "argon2" not in envelope:
        raise DecryptError(f"{path} is not a MySecret vault-envelope.json")
    return envelope


def _hex(value, expected_len, what):
    try:
        raw = bytes.fromhex(value)
    except (TypeError, ValueError):
        raise DecryptError(f"Invalid hex in envelope field '{what}'")
    if expected_len is not None and len(raw) != expected_len:
        raise DecryptError(f"Envelope field '{what}' has an unexpected length")
    return raw


def _unwrap(wrapped: dict, wrapping_key: bytes, aad: bytes, what: str) -> bytes:
    iv = _hex(wrapped.get("iv"), 12, f"{what}.iv")
    tag = _hex(wrapped.get("tag"), 16, f"{what}.tag")
    ciphertext = _hex(wrapped.get("ciphertext"), 32, f"{what}.ciphertext")
    try:
        key = AESGCM(wrapping_key).decrypt(iv, ciphertext + tag, aad)
    except InvalidTag:
        raise DecryptError("Wrong password / recovery phrase (or the envelope was modified)")
    if len(key) != 32:
        raise DecryptError("Unexpected vault key length")
    return key


def key_from_password(envelope: dict, password: str) -> bytes:
    """Master password -> Argon2id -> unwraps the vault key."""
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise DecryptError("'argon2-cffi' is required for --password:\n  pip install argon2-cffi")

    params = envelope["argon2"]
    memory, iterations, parallelism = params["memory"], params["iterations"], params["parallelism"]
    # Refuse downgraded / absurd parameters, exactly like the plugin.
    if not (MIN_MEMORY_KIB <= memory <= MAX_MEMORY_KIB
            and MIN_ITERATIONS <= iterations <= MAX_ITERATIONS
            and MIN_PARALLELISM <= parallelism <= MAX_PARALLELISM):
        raise DecryptError("The envelope has out-of-range Argon2id parameters (tampered?)")

    pass_key = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=_hex(params["salt"], 16, "argon2.salt"),
        time_cost=iterations,
        memory_cost=memory,
        parallelism=parallelism,
        hash_len=32,
        type=Type.ID,
    )
    return _unwrap(envelope["vaultKeyEnvelope"], pass_key, b"vault-envelope", "vaultKeyEnvelope")


def key_from_mnemonic(envelope: dict, mnemonic: str) -> bytes:
    """24 words -> PBKDF2(salt = recoveryEnvelope.salt) -> unwraps the vault key.

    NOTE: the phrase is NOT the vault key. The plugin derives a *recovery key*
    with a random per-vault salt (not the BIP-39 "mnemonic" salt) and uses it
    to wrap the vault key in `recoveryEnvelope`.
    """
    recovery = envelope.get("recoveryEnvelope")
    if not recovery:
        raise DecryptError("This vault has no recovery phrase configured (password-only vault).")

    clean = " ".join(mnemonic.strip().lower().split())
    if len(clean.split(" ")) != 24:
        raise DecryptError("The recovery phrase must have exactly 24 words")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=_hex(recovery["salt"], 16, "recoveryEnvelope.salt"),
        iterations=2048,
    )
    recovery_key = kdf.derive(clean.encode("utf-8"))
    return _unwrap(recovery, recovery_key, b"recovery-envelope", "recoveryEnvelope")


# ---------------------------------------------------------------------------
# File formats
# ---------------------------------------------------------------------------

def _aad(relative_path: str) -> bytes:
    return unicodedata.normalize("NFC", relative_path.replace("\\", "/").lstrip("/")).encode("utf-8")


def is_armored(raw: bytes) -> bool:
    head = raw[:3]
    body = raw[3:] if head == b"\xef\xbb\xbf" else raw
    return body.lstrip(b" \t\r\n").startswith(ARMORED_START)


def decrypt_armored(raw: bytes, relative_path: str, vault_key: bytes) -> bytes:
    start = raw.find(ARMORED_START)
    end = raw.find(ARMORED_END)
    if start == -1 or end == -1 or end <= start:
        raise DecryptError("Not a valid armored MySecret file")

    lines = raw[start + len(ARMORED_START):end].decode("ascii", errors="strict").splitlines()
    iv_b64 = tag_b64 = ""
    body = []
    in_body = False
    for line in lines:
        text = line.strip()
        if not in_body:
            if text == "":
                if iv_b64 and tag_b64:
                    in_body = True
                continue
            key, _, value = text.partition(":")
            key = key.strip().lower()
            if key == "iv":
                iv_b64 = value.strip()
            elif key == "tag":
                tag_b64 = value.strip()
        else:
            body.append(text)

    if not iv_b64 or not tag_b64:
        raise DecryptError("Malformed armored file (missing IV or Tag)")

    iv = base64.b64decode(iv_b64)
    tag = base64.b64decode(tag_b64)
    ciphertext = base64.b64decode("".join(body)) if body else b""
    try:
        return AESGCM(vault_key).decrypt(iv, ciphertext + tag, _aad(relative_path))
    except InvalidTag:
        raise DecryptError(
            "Authentication failed: wrong key or the --relative-path does not match the vault path "
            "the file was encrypted for (the path is part of the authenticated data)"
        )


def is_binary_container(raw: bytes) -> bool:
    return len(raw) >= BINARY_HEADER_LENGTH and raw[:4] == BINARY_MAGIC and raw[4] == 1


def decrypt_binary(raw: bytes, relative_path: str, vault_key: bytes) -> bytes:
    iv = raw[5:17]
    tag = raw[17:33]
    ciphertext = raw[33:]
    try:
        return AESGCM(vault_key).decrypt(iv, ciphertext + tag, _aad(relative_path))
    except InvalidTag:
        raise DecryptError("Authentication failed: wrong key or wrong --relative-path")


def decrypt_bytes(raw: bytes, relative_path: str, vault_key: bytes):
    """Returns (bytes, was_encrypted)."""
    if is_binary_container(raw):
        return decrypt_binary(raw, relative_path, vault_key), True
    if is_armored(raw):
        return decrypt_armored(raw, relative_path, vault_key), True
    return raw, False


# ---------------------------------------------------------------------------
# Vault processing
# ---------------------------------------------------------------------------

def process_vault(vault_dir: Path, output_dir: Path, vault_key: bytes) -> int:
    vault_dir = vault_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir == vault_dir or vault_dir in output_dir.parents:
        raise DecryptError("--output must be OUTSIDE the vault directory")

    print(f"\n[+] Decrypting {vault_dir} -> {output_dir}")
    decrypted = copied = errors = 0

    for root, dirs, files in os.walk(vault_dir):
        # Hidden directories (.obsidian, .git, .trash...) are never encrypted by the plugin.
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            full = Path(root) / name
            rel = full.relative_to(vault_dir).as_posix()
            if name.startswith(".") and "/" not in rel:
                continue  # root dotfiles are never encrypted
            target = output_dir / rel
            try:
                raw = full.read_bytes()
                data, was_encrypted = decrypt_bytes(raw, rel, vault_key)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                if was_encrypted:
                    decrypted += 1
                else:
                    copied += 1
            except (DecryptError, OSError, ValueError) as exc:
                errors += 1
                print(f"[-] {rel}: {exc}")

    print("\n[✓] Done")
    print(f"    - Decrypted files:        {decrypted}")
    print(f"    - Copied (not encrypted): {copied}")
    print(f"    - Errors:                 {errors}")
    return 0 if errors == 0 else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="MySecret standalone vault decryptor")
    parser.add_argument("--vault", help="Path to your Obsidian vault directory")
    parser.add_argument("--output", help="Destination directory (must be outside the vault)")
    parser.add_argument("--envelope", help="Path to vault-envelope.json (default: autodetected in --vault)")
    parser.add_argument("--mnemonic", help="24-word recovery phrase")
    parser.add_argument(
        "--password", nargs="?", const="", default=None,
        help="Master password. Omit the value to be prompted (recommended: it stays out of shell history)",
    )
    parser.add_argument("--file", help="Decrypt a single file")
    parser.add_argument("--relative-path", help="Vault-relative path of --file (REQUIRED for a single file)")
    args = parser.parse_args()

    if args.mnemonic is None and args.password is None:
        parser.error("Provide --mnemonic or --password.")
    if not args.vault and not args.envelope:
        parser.error("Provide --vault (or --envelope together with --file).")

    try:
        envelope = load_envelope(find_envelope(Path(args.vault) if args.vault else Path("."), args.envelope))

        if args.mnemonic is not None:
            print("[*] Unwrapping the vault key with the recovery phrase...", file=sys.stderr)
            vault_key = key_from_mnemonic(envelope, args.mnemonic)
        else:
            password = args.password or getpass.getpass("Master password: ")
            print("[*] Deriving the key with Argon2id (a few hundred ms)...", file=sys.stderr)
            vault_key = key_from_password(envelope, password)
        print("[+] Vault key recovered.", file=sys.stderr)

        if args.file:
            if not args.relative_path:
                parser.error("--relative-path is required with --file (it is part of the authenticated data).")
            raw = Path(args.file).read_bytes()
            data, was_encrypted = decrypt_bytes(raw, args.relative_path, vault_key)
            if not was_encrypted:
                print("[!] The file is not encrypted; printing it as is.", file=sys.stderr)
            sys.stdout.buffer.write(data)
            return 0

        if not args.vault:
            parser.error("--vault is required to decrypt a whole vault.")
        if not args.output:
            parser.error("--output is required when decrypting a vault.")
        return process_vault(Path(args.vault), Path(args.output), vault_key)

    except DecryptError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
