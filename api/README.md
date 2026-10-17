# HelixLock API

FastAPI backend for the Layer 1 encryption engine. It supports plain text,
hex-encoded binary data, and file uploads.

## Requirements

- Python 3.11 or newer
- pip

Run all commands below from the **project root** (`Data-Security-Algorithm`),
not from the `api` directory. No database or external service is required.

## Set up and run on Windows (PowerShell)

```powershell
cd C:\Users\vijin\Documents\Data-Security-Algorithm
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

The commands use the virtual environment's Python directly, so activation and
PowerShell execution-policy changes are unnecessary. Adjust the project path
if your checkout is elsewhere. On later runs, use only the final command.

## Set up and run on Linux or macOS

```bash
cd Data-Security-Algorithm
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

Keep the terminal running. Press **Ctrl+C** to stop the server. `--reload`
automatically restarts it after source changes and is intended for development.

## Open the API

| URL | Purpose |
| --- | --- |
| http://127.0.0.1:8000/docs | Swagger UI: try the API interactively |
| http://127.0.0.1:8000/redoc | API reference |
| http://127.0.0.1:8000/health | Health check |
| http://127.0.0.1:8000/openapi.json | OpenAPI schema |

The health check returns `{"status":"ok","version":"0.1.0"}`.
The root URL `/` has no page; use `/docs` instead.

## Encrypt and decrypt normal text

In Swagger UI, expand **POST /api/v1/encrypt**, choose **Try it out**, select
the text example, and send:

```json
{
  "plaintext": "Hello world",
  "layer": "layer1"
}
```

The API encodes text as UTF-8, including Unicode and emoji. It returns
`ciphertext_hex`, `key_hex`, and byte lengths. A fresh 32-byte key is generated
when `key_hex` is omitted. Save the returned key to decrypt the result.

For **POST /api/v1/decrypt**, copy the ciphertext and key from that response:

```json
{
  "ciphertext_hex": "<ciphertext_hex from the encrypt response>",
  "key_hex": "<key_hex from the encrypt response>",
  "layer": "layer1"
}
```

Replace both placeholders with the actual hex values. The response contains
`"plaintext": "Hello world"` and `"plaintext_hex": "48656c6c6f20776f726c64"`.

You can also run a complete round trip in PowerShell:

```powershell
$encrypted = Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8000/api/v1/encrypt' `
  -ContentType 'application/json' `
  -Body (@{ plaintext = 'Hello world'; layer = 'layer1' } | ConvertTo-Json)

$decrypted = Invoke-RestMethod -Method Post `
  -Uri 'http://127.0.0.1:8000/api/v1/decrypt' `
  -ContentType 'application/json' `
  -Body (@{
    ciphertext_hex = $encrypted.ciphertext_hex
    key_hex = $encrypted.key_hex
    layer = 'layer1'
  } | ConvertTo-Json)

$decrypted.plaintext
```

## Binary data and files

For binary JSON input, send `plaintext_hex` instead of `plaintext`:

```json
{
  "plaintext_hex": "00ff80fe",
  "layer": "layer1"
}
```

Supply exactly one non-null input: `plaintext` or `plaintext_hex`. Empty text
is supported. Text that looks like hex is still treated as text when sent in
`plaintext`. Keys and ciphertext always use hex encoding. Decryption returns
`plaintext: null` for bytes that are not valid UTF-8; `plaintext_hex` preserves
the complete binary result.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Check server readiness |
| GET | `/api/v1/generate-key` | Generate a key; optional `length` query parameter, default 32 bytes |
| POST | `/api/v1/encrypt` | Encrypt text or hex bytes |
| POST | `/api/v1/decrypt` | Decrypt hex ciphertext |
| POST | `/api/v1/encrypt-file` | Upload a multipart `file` and receive encrypted bytes |
| POST | `/api/v1/decrypt-file` | Upload an encrypted multipart `file` and receive original bytes |

For file encryption, pass an optional `X-HelixLock-Key-Hex` header or let the
server generate a key. The encryption response includes that header with the
key used. Supply the same header when decrypting the file. These endpoints are
also available in Swagger UI. Currently, only `layer1` is implemented.

## Run tests

From the project root on Windows:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

On Linux or macOS, use `.venv/bin/python -m pytest -q`.

## Troubleshooting

- **Cannot import `api`:** run the server command from the project root.
- **Missing module:** install `requirements.txt` using the same Python
  interpreter that starts the server.
- **Port 8000 is occupied:** stop the existing server before starting another
  instance. In PowerShell, inspect it with
  `Get-NetTCPConnection -LocalPort 8000 -State Listen`.
- **HTTP 422 when encrypting:** use `plaintext` for normal text; use
  `plaintext_hex` only for valid hex. Do not provide both non-null inputs.
- **Decryption fails:** check that the key and ciphertext are copied completely
  from the matching encryption response.
