import sys
import json
from cryptography.fernet import Fernet, InvalidToken

def main():
    try:
        input_str = sys.stdin.read().strip()
        if not input_str:
            print(json.dumps({"error": "Empty input from stdin"}))
            sys.exit(1)

        input_data = json.loads(input_str)

        key_str = input_data.get("key")
        encrypted = input_data.get("process", {}).get("parametersEncrypted")

        if not key_str or not encrypted:
            print(json.dumps({"error": "Missing key or parametersEncrypted"}))
            sys.exit(1)

        clean_key = key_str.strip().encode('utf-8')
        fernet = Fernet(clean_key)

        decrypted_bytes = fernet.decrypt(encrypted.encode('utf-8'))
        parameters = json.loads(decrypted_bytes.decode('utf-8'))

        # Restore original structure
        input_data["process"]["parameters"] = parameters
        input_data["process"].pop("parametersEncrypted", None)

        print(json.dumps(input_data, ensure_ascii=False))

    except InvalidToken:
        print(json.dumps({"error": "InvalidToken - Key mismatch or corrupted data"}))
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"JSON error: {str(e)}"}))
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {str(e)}"}))

if __name__ == "__main__":
    main()