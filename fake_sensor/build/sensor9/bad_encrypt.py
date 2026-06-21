"""
bad_encrypt.py
==============
Simulate incorrect encryption for sensor9 testing.
Produces the same wrapper format { "key": "...", "encrypted": "..." }
but the "encrypted" blob is produced by a different method (base64 of the JSON),
so the Node-RED Fernet decrypt will fail (wrong version, HMAC fail, etc.).

This simulates a message that looks correctly formatted but was encrypted
with an incompatible method.

Usage (called from test script):
  python3 bad_encrypt.py encrypt temp_message.json --output final_message.json
"""

import json
import base64
import argparse
import os
from cryptography.fernet import Fernet

def load_json_tolerant(path: str) -> dict:
    with open(path, "r") as f:
        text = f.read()
    # simple tolerant load if needed
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # strip trailing commas etc if needed
        import re
        text = re.sub(r",\s*([}\]])", r"\1", text)
        return json.loads(text)


def bad_encrypt_entire(input_path: str, output_path: str = "final_message.json") -> None:
    data = load_json_tolerant(input_path)

    message_bytes = json.dumps(data).encode("utf-8")

    # Real encryption key (never exposed in the wrapper)
    real_encryption_key = Fernet.generate_key()
    fernet = Fernet(real_encryption_key)
    correct_length_token = fernet.encrypt(message_bytes).decode("utf-8")

    # Different key placed in the wrapper (this is what Node-RED will use)
    wrong_key_for_wrapper = Fernet.generate_key().decode("utf-8")

    wrapper = {
        "key": wrong_key_for_wrapper,
        "encrypted": correct_length_token
    }

    # Force the serialized size to exactly match a normal message (2802 bytes)
    # by padding the encrypted field if needed. This guarantees it passes the
    # size check in Prepare for Decryption and reaches the actual decrypt step.
    wrapper_str = json.dumps(wrapper, indent=2)
    current_size = len(wrapper_str.encode("utf-8"))
    target_size = 2802
    if current_size < target_size:
        pad_len = target_size - current_size
        wrapper["encrypted"] = wrapper["encrypted"] + ("A" * pad_len)
        wrapper_str = json.dumps(wrapper, indent=2)
    # If larger (unlikely), we could trim but for now assume it's close or pad more

    with open(output_path, "w") as f:
        f.write(wrapper_str)

    final_size = os.path.getsize(output_path)
    print(f"Produced wrapper with mismatched key (final size {final_size} bytes) -> {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Produce a wrapper that looks correct but is encrypted with the wrong method."
    )
    parser.add_argument("action", choices=["encrypt"])
    parser.add_argument("input")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    output = args.output or "final_message.json"
    if args.action == "encrypt":
        bad_encrypt_entire(args.input, output)


if __name__ == "__main__":
    main()
