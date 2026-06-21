"""
param_crypto.py
===============
Encrypt / decrypt the **entire** JSON message using Fernet symmetric encryption
(AES-128-CBC + HMAC-SHA256).

Usage
-----
  # Encrypt the full message
  python param_crypto.py encrypt final_clear.json --output final_message.json

  # Decrypt (for testing)
  python param_crypto.py decrypt final_message.json --output decrypted.json

The encryption key is saved to `secret.key` (or loaded from it).
The output is a small wrapper:
{
  "key": "base64-fernet-key",
  "encrypted": "Fernet-token-of-the-whole-original-json"
}
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


def encrypt_entire(input_path: str,
                   output_path: str = "encrypted_message.json",
                   key_file: str = "secret.key") -> None:
    """Encrypt the entire JSON file and produce a {key, encrypted} wrapper."""
    data = load_json_tolerant(input_path)

    # Serialize the whole message
    message_bytes = json.dumps(data).encode("utf-8")

    key = generate_key(key_file)
    fernet = Fernet(key)
    token = fernet.encrypt(message_bytes).decode("utf-8")

    wrapper = {
        "key": key.decode("utf-8"),
        "encrypted": token
    }

    with open(output_path, "w") as f:
        json.dump(wrapper, f, indent=2)

    print(f"Encrypted entire message → {output_path}")
    print(f"Key saved to {key_file}")


def decrypt_entire(input_path: str,
                   output_path: str = "decrypted_message.json",
                   key_file: str = "secret.key") -> None:
    """Decrypt a {key, encrypted} wrapper back to the original full JSON."""
    with open(input_path, "r") as f:
        wrapper = json.load(f)

    if "key" not in wrapper or "encrypted" not in wrapper:
        raise KeyError("Input must contain 'key' and 'encrypted' (new full-message format).")

    token = wrapper["encrypted"].encode("utf-8")

    # Prefer key embedded in the wrapper (as sent by sensors)
    key_str = wrapper.get("key")
    if key_str:
        key = key_str.encode("utf-8")
    else:
        key = load_key(key_file)

    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(token)
    decrypted = json.loads(decrypted_bytes.decode("utf-8"))

    with open(output_path, "w") as f:
        json.dump(decrypted, f, indent=2)

    print(f"Decrypted full message → {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt / decrypt the entire JSON message with Fernet."
    )
    parser.add_argument("action", choices=["encrypt", "decrypt"],
                        help="Action to perform")
    parser.add_argument("input",
                        help="Path to the input JSON file")
    parser.add_argument("--output", default=None,
                        help="Path for the output JSON")
    parser.add_argument("--key-file", default="secret.key",
                        help="Path to the Fernet key file (default: secret.key)")

    args = parser.parse_args()
    output = args.output

    if args.action == "encrypt":
        output = output or "encrypted_message.json"
        encrypt_entire(args.input, output, args.key_file)
    else:
        output = output or "decrypted_message.json"
        decrypt_entire(args.input, output, args.key_file)


if __name__ == "__main__":
    main()