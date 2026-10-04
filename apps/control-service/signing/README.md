# Product code signing (K16)

CI/local builds produce **unsigned** Windows/Ubuntu installers. An **admin** signs them in the desktop Admin → Code Signing tab (or via the control API) before distribution.

This is distinct from gateway MQTT/TLS certs (`certs/` / rotate-server).

## Flow: unsigned CI → admin-signed ship

```
┌─────────────┐     artifacts      ┌──────────────────┐     signed + SHA256SUMS
│  CI / local │ ────────msi/exe──► │ Admin Code       │ ─────────────────────► USB / release
│  tauri build│      AppImage/deb  │ Signing tab      │
└─────────────┘                    │ (keyring + PIN)  │
                                   └──────────────────┘
```

1. **Build (CI or developer laptop)**  
   `cargo tauri build` → `src-tauri/target/release/bundle/`  
   (`.msi` / NSIS `.exe` / `.AppImage`). Do **not** put org Authenticode/GPG secrets in CI for v1.

2. **Admin unlock**  
   Open `admin.html` (Setup Wizard → Admin). Set/unlock local PIN (OS keyring).

3. **Load signing identity**  
   - Windows: path to `.pfx` + passphrase (passphrase → keyring; path/thumbprint → settings).  
   - Ubuntu: GPG key id + passphrase.

4. **Sign**  
   Scan build folder or paste paths → Sign. Control service invokes:
   - Windows: `osslsigncode` (preferred) or `signtool`
   - Linux: `gpg --detach-sign` → `artifact.sig`  
   Missing tools return a clear error (no silent skip).

5. **Export**  
   Signed outputs + `SHA256SUMS` land in the export folder (default: app data `signed-export/`).  
   `audit_log` records actor, artifact paths, tool, thumbprint/key id — **never** passphrases or private keys.

## Tools

| Platform | Tool | Install hint |
|----------|------|--------------|
| Windows Authenticode | `osslsigncode` or `signtool` | `apt install osslsigncode` / Windows SDK |
| Ubuntu AppImage/`.deb` | `gpg` / `gpg2` | `apt install gnupg` |

## API (control service)

Authenticated (`IOTGW_API_TOKEN` when set):

- `GET  /api/v1/admin/signing/tools`
- `POST /api/v1/admin/signing/list-artifacts` `{"folder":"..."}`
- `POST /api/v1/admin/signing/sign` — body includes artifact paths + identity fields

Desktop wizard proxies the same operations under `/api/admin/signing/*` after admin unlock (`X-Admin-Session`).

## Out of v1

Cloud HSM/KMS, Microsoft Store submission, macOS notarization, multi-admin RBAC server.
