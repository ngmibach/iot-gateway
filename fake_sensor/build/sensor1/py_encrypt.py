"""
param_crypto.py
===============
Encrypt / decrypt the `process.parameters` section of a JSON file
using Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).

Usage
-----
  python param_crypto.py encrypt sample_data.json
  python param_crypto.py decrypt encrypted_data.json --key-file secret.key

The encryption key is saved to  `secret.key`  (or loaded from it).
The output JSON replaces `process.parameters` with a single
`process.parametersEncrypted` token.
"""

import json
import re
import sys
import os
import argparse
from cryptography.fernet import Fernet


def load_json_tolerant(path: str) -> dict:
    """Load JSON, stripping trailing commas before closing braces/brackets."""
    with open(path, "r") as f:
        text = f.read()
    # Remove trailing commas before } or ]
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return json.loads(text)

def generate_key(key_file: str = "secret.key") -> bytes:
    """Generate a new Fernet key and save it to *key_file*."""
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    return key


def load_key(key_file: str = "secret.key") -> bytes:
    """Load an existing Fernet key from *key_file*."""
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Key file '{key_file}' not found. Run encrypt first.")
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_parameters(input_path: str,
                        output_path: str = "encrypted_data.json",
                        key_file: str = "secret.key") -> None:
    data = load_json_tolerant(input_path)

    if "process" not in data or "parameters" not in data["process"]:
        raise KeyError("'process.parameters' not found in the JSON.")

    # Serialise the parameters to bytes
    params_bytes = json.dumps(data["process"]["parameters"]).encode("utf-8")

    # Encrypt
    key = generate_key(key_file)
    fernet = Fernet(key)
    token = fernet.encrypt(params_bytes).decode("utf-8")   # store as string

    # Swap parameters → parametersEncrypted
    del data["process"]["parameters"]
    data["process"]["parametersEncrypted"] = token

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

def decrypt_parameters(input_path: str,
                        output_path: str = "decrypted_data.json",
                        key_file: str = "secret.key") -> None:
    with open(input_path, "r") as f:
        data = json.load(f)

    if "process" not in data or "parametersEncrypted" not in data["process"]:
        raise KeyError("'process.parametersEncrypted' not found in the JSON.")

    token = data["process"]["parametersEncrypted"].encode("utf-8")

    key = load_key(key_file)
    fernet = Fernet(key)
    params_bytes = fernet.decrypt(token)                    # raises if tampered
    params = json.loads(params_bytes.decode("utf-8"))

    # Restore original structure
    del data["process"]["parametersEncrypted"]
    data["process"]["parameters"] = params

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

def main():
    parser = argparse.ArgumentParser(
        description="Encrypt / decrypt process.parameters in a JSON file."
    )
    parser.add_argument("action", choices=["encrypt", "decrypt"],
                        help="Action to perform")
    parser.add_argument("input",
                        help="Path to the input JSON file")
    parser.add_argument("--output", default=None,
                        help="Path for the output JSON (default: encrypted_data.json / decrypted_data.json)")
    parser.add_argument("--key-file", default="secret.key",
                        help="Path to the Fernet key file (default: secret.key)")

    args = parser.parse_args()
    output = args.output

    if args.action == "encrypt":
        output = output or "encrypted_data.json"
        encrypt_parameters(args.input, output, args.key_file)
    else:
        output = output or "decrypted_data.json"
        decrypt_parameters(args.input, output, args.key_file)


if __name__ == "__main__":
    main()