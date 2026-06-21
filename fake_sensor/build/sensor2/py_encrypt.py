"""
py_encrypt.py
=============
Encrypt / decrypt the **entire** JSON message using Fernet symmetric encryption
(AES-128-CBC + HMAC-SHA256).

Usage
-----
  python py_encrypt.py encrypt sample_data.json --output final_message.json
  python py_encrypt.py decrypt final_message.json --output decrypted.json

The encryption key is saved to `secret.key` (or loaded from it).
The output is a wrapper:
{
  "key": "base64-fernet-key",
  "encrypted": "<Fernet token of the whole original JSON>"
}
"""

import json
import re
import os
import argparse
from cryptography.fernet import Fernet


def load_json_tolerant(path: str) -> dict:
    """Load JSON, stripping trailing commas before closing braces/brackets."""
    with open(path, "r") as f:
        text = f.read()
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
    """Encrypt the whole JSON and emit {key, encrypted} wrapper."""
    data = load_json_tolerant(input_path)
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


def decrypt_entire(input_path: str,
                   output_path: str = "decrypted_message.json",
                   key_file: str = "secret.key") -> None:
    """Decrypt a {key, encrypted} wrapper back to the original full JSON."""
    with open(input_path, "r") as f:
        wrapper = json.load(f)

    if "key" not in wrapper or "encrypted" not in wrapper:
        raise KeyError("Wrapper must contain 'key' and 'encrypted'.")

    token = wrapper["encrypted"].encode("utf-8")

    key = wrapper.get("key", "").encode("utf-8") or load_key(key_file)

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
        encrypt_entire(args.input, output or "encrypted_message.json", args.key_file)
    else:
        decrypt_entire(args.input, output or "decrypted_message.json", args.key_file)


if __name__ == "__main__":
    main()