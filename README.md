# encrypt-vault

A minimalist self-hosted file server where the server **never sees your plaintext data**. All encryption and decryption happens entirely in the browser using the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) — no libraries, no dependencies.

## How it works

```
Browser                                 Server
──────────────────────────────          ──────────────────────────
Password → PBKDF2 → AES-256-GCM key    Stores only encrypted blobs
File → encrypt in browser → upload ──► POST /upload  →  *.enc file
GET /file/<uuid> ◄─────────────────    Serves raw bytes, no decryption
Decrypt in browser → display
```

- The server stores `.enc` blobs and nothing else
- Your password never leaves your device
- Wrong password → `OperationError` from the browser's crypto engine — no oracle
- `Cache-Control: no-store` on every response prevents browser disk caching

## Security properties

| What an attacker with server access sees | What they cannot see |
|---|---|
| Number of files | Filenames or MIME types (encrypted in metadata) |
| Approximate file size bucket | Exact file sizes (padded to power-of-2 buckets) |
| Upload/access timestamps (if `noatime` not set) | File contents |
| — | Your password |

**Encryption:** AES-256-GCM (authenticated — detects tampering)  
**Key derivation:** PBKDF2-SHA256, 210,000 iterations, 16-byte random salt per file  
**Metadata:** encrypted separately before the file data; decrypted first to fail fast on wrong passwords  
**Size obfuscation:** files padded to the nearest power-of-2 bucket (≤128 MB) or 16 MB boundary (>128 MB) before encryption

## Requirements

- Python 3.6+ (standard library only — no pip installs needed)
- A modern browser (Chrome 37+, Firefox 34+, Safari 11.1+)

## Setup

```bash
git clone https://github.com/vikarag/encrypt-vault
cd encrypt-vault
python3 server.py
# → Vault listening on http://localhost:9000
```

Open `http://localhost:9000` in your browser.

### HTTPS (required for non-localhost access)

Browsers restrict the Web Crypto API to [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts). For network access you need TLS.

**Option A — Tailscale (recommended for personal use)**

If your machine is on a [Tailscale](https://tailscale.com) network, you can get a free, browser-trusted Let's Encrypt certificate:

```bash
# Enable HTTPS in your Tailscale admin panel first, then:
sudo tailscale cert \
  --cert-file cert.pem \
  --key-file  key.pem \
  your-node.your-tailnet.ts.net

sudo chown $USER cert.pem key.pem
chmod 644 cert.pem
chmod 600 key.pem

python3 server.py --host 0.0.0.0 --port 9200
# → Vault listening on https://your-node.your-tailnet.ts.net:9200
```

The server automatically detects `cert.pem` / `key.pem` in its directory and enables HTTPS.

**Option B — Self-signed certificate**

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 3650 -nodes -subj "/CN=vault" \
  -addext "subjectAltName=IP:127.0.0.1,IP:<your-ip>"
```

The browser will show a one-time warning; click "Advanced → Proceed" to accept it.

### Auto-renew Tailscale certificate

Edit `renew-cert.sh` with your paths and hostname, then set up a monthly systemd timer:

```bash
# /etc/systemd/system/vault-cert-renew.service
[Unit]
Description=Renew Tailscale TLS certificate for Vault
After=network-online.target tailscaled.service

[Service]
Type=oneshot
ExecStart=/path/to/vault/renew-cert.sh

# /etc/systemd/system/vault-cert-renew.timer
[Unit]
Description=Monthly renewal of Vault TLS certificate

[Timer]
OnCalendar=monthly
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now vault-cert-renew.timer
```

### Run on boot (systemd)

```ini
# /etc/systemd/system/vault.service
[Unit]
Description=Vault encrypted file server
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/path/to/vault
ExecStart=/usr/bin/python3 /path/to/vault/server.py --host 0.0.0.0 --port 9200
Restart=on-failure
RestartSec=5
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault.service
```

## Usage

| Action | How |
|---|---|
| **Upload files** | Choose files → enter password → Encrypt & Upload |
| **Fetch from URL** | Paste a URL → Fetch & Encrypt (server fetches, browser encrypts) |
| **View a file** | Click View next to a file, enter password |
| **Reveal filenames** | Click "Reveal Names" — decrypts metadata only (fast, no full download) |
| **Delete a file** | Click × next to a file |
| **Virtual keyboard** | Click ⌨ next to the password field — keys are shuffled on every open |

Session auto-clears after 10 minutes of inactivity (password wiped, viewer closed, clipboard cleared).

## Server options

```
python3 server.py [--host HOST] [--port PORT]

  --host    Bind address (default: localhost)
  --port    Port number  (default: 9000)
```

## OS hardening (recommended)

For maximum forensic resistance on Linux:

```bash
# Disable swap — prevents decrypted browser memory from being paged to disk
sudo swapoff -a
# Comment out swap entries in /etc/fstab to make permanent

# Disable hibernation — prevents full RAM dump to disk
sudo systemctl mask hibernate.target hybrid-sleep.target

# Disable core dumps — prevents crash dumps containing decrypted memory
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p

# Add noatime to the vault's mount in /etc/fstab to hide file access times
# Example: UUID=... /mnt/data ext4 defaults,nofail,noatime 0 2
sudo mount -o remount /mnt/your-drive
```

## Password recommendations

Use a **6-word diceware passphrase**. At 210,000 PBKDF2 iterations, even a well-funded offline attack cannot crack a strong passphrase in any reasonable timeframe.

```bash
# Generate one locally
python3 -c "
import secrets, pathlib
words = pathlib.Path('/usr/share/dict/words').read_text().splitlines()
words = [w for w in words if w.isalpha() and 4 <= len(w) <= 8]
print('-'.join(secrets.choice(words) for _ in range(6)))
"
```

Never reuse a password from another service. The password is the only thing protecting your files if someone obtains the `.enc` blobs.

## File format

Each `.enc` file is a self-contained binary blob:

```
Offset   Len   Field
──────   ───   ─────────────────────────────────────────────────────────────
0        4     Magic: "ENCF"
4        2     Version: 0x0001 (big-endian)
6        2     Flags: 0x0000
8        4     MetaLen: length of EncryptedMeta (big-endian)
12       16    Salt (random, used for PBKDF2 key derivation)
28       12    Meta-IV (random, AES-GCM IV for metadata block)
40       ML    EncryptedMeta: AES-GCM(key, IV, JSON + padding) + 16-byte tag
40+ML    12    Data-IV (random, AES-GCM IV for file data)
52+ML    N+16  EncryptedData: AES-GCM(key, IV, padded plaintext) + 16-byte tag
```

Encrypted metadata JSON: `{"name": "file.jpg", "mime": "image/jpeg", "size": 204800, "uploadedAt": 1745000000}`

## License

MIT
