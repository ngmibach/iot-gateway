# Product code signing (K16)

CI/local builds produce **unsigned** Windows/Ubuntu installers. An **admin** signs them in the desktop Admin → Code Signing tab before distribution.

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
   - Windows: absolute path to `.pfx` + passphrase (passphrase → keyring; path/thumbprint → settings).  
   - Ubuntu: GPG key id + passphrase.

4. **Sign**  
   Scan build folder or paste **absolute** paths → Sign. Desktop wizard invokes
   `apps/control-service/signing/` helpers:
   - Windows: `osslsigncode` (preferred) or `signtool`
   - Linux: `gpg --detach-sign` → `artifact.sig`  
   Missing tools return a clear error (no silent skip).

5. **Export**  
   Signed outputs + `SHA256SUMS` land in the export folder (default: app data `signed-export/`).  
   `audit_log` records actor, artifact paths, tool, thumbprint/key id — **never** passphrases or private keys.

## HTTP surface (v1)

Signing is exposed only via the desktop wizard Admin APIs (after PIN unlock):

- `GET  /api/admin/signing/tools`
- `POST /api/admin/signing/list-artifacts` `{"folder":"/abs/path"}`
- `POST /api/admin/signing/sign`
- `POST /api/admin/signing/open-export` (confined to app data dir or last sign export)

Shared logic lives in this Python package; there is no separate FastAPI signing router in v1.

### Trust boundary

An unlocked admin session (local PIN) may list/sign **absolute** filesystem paths on the operator machine — intentional for “paste a build folder.” Paths must be absolute and must not contain NUL. `open-export` is further confined to the app data directory or the last successful sign export. Treat admin unlock as local FS access for signing.

## Tools

| Platform | Tool | Install hint |
|----------|------|--------------|
| Windows Authenticode | `osslsigncode` or `signtool` | `apt install osslsigncode` / Windows SDK |
| Ubuntu AppImage/`.deb` | `gpg` / `gpg2` | `apt install gnupg` |

## Out of v1

Cloud HSM/KMS, Microsoft Store submission, macOS notarization, multi-admin RBAC server.
