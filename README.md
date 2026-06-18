# RGB proxy server

RGB proxy server facilitates relay of client-side data between RGB wallets,
supporting the improved transfer workflow with sender-side proxy, signed ACKs,
encrypted payloads (encryption is performed client-side; the server stores
opaque blobs) and reusable invoices.

The API implements protocol version **1.0** of the
[RGB HTTP JSON-RPC protocol](https://github.com/RGB-Tools/rgb-http-json-rpc).

## Transfer workflow

A typical non-donation transfer involves both a **recipient proxy** and a
**sender proxy**:

1. **Recipient** generates a fresh key pair for the invoice and reserves the
   invoice ID on each recipient transport endpoint (`invoice.prepare`), with
   its expiration, the invoice pubkey and a quota (the number of transfers the
   invoice can receive, 1 for a single-use invoice).
2. **Recipient** creates the invoice, including its pubkey (`pk`) and optional
   encryption preference (`enc`), and shares it.
3. **Sender** generates a fresh key pair for the operation, computes the
   invoice ID and checks that the invoice can accept a transfer and which
   proof of work difficulty is required (`invoice.check`).
4. **Sender** posts the per-transfer data to its sender proxy, including the
   encrypted signed TXs (`ack.prepare`).
5. **Sender** posts the signed consignment (and media) to the recipient proxy
   (`consignment.post`, `media.post`), including the sender transport
   endpoint, the sender pubkey and the proof of work. This creates a transfer
   under the invoice, identified by a transfer ID derived from the invoice ID
   and the sender pubkey.
6. **Recipient** lists the transfers of the invoice (`transfer.list`),
   fetches consignment and media (`consignment.get`, `media.get`), decrypts
   them client-side, validates them, then posts a signed ACK to the sender
   proxy (`ack.post`) and receives the encrypted signed TX.
7. **Recipient** signals that the transfer data has been saved
   (`transfer.retrieved`), so the proxy can delete it, or deletes the transfer
   altogether, freeing its quota slot (`transfer.delete`).
8. **Sender** retrieves the ACK signatures from the sender proxy (`ack.get`)
   as proof of acceptance.
9. **Either party** can broadcast the Bitcoin transaction.

Donations skip step 4 (`ack.prepare`) and part of step 6 (no ACK / TX-release machinery).

### Identifiers

- invoice ID: hex-encoded SHA-256 of the UTF-8 concatenation of
  `rgb-proxy-server/invoice/v1`, the invoice beneficiary (blinded UTXO or
  address, in its canonical string form) and the invoice pubkey; the proxy only
  checks its format
- transfer ID: hex-encoded SHA-256 of the UTF-8 concatenation of
  `rgb-proxy-server/transfer/v1`, the invoice ID and `sender_pk`; the proxy
  verifies it on `consignment.post`

IDs, hashes, pubkeys and signatures are lowercase hex strings (64 characters,
128 for signatures). `media_id` is an opaque 64-character lowercase hex string.

### Proof of work

To protect invoices that are shared publicly, `consignment.post` can require
a proof of work: a `pow_nonce` such that
`SHA-256(transfer_id ‖ pow_timestamp ‖ pow_nonce)` (UTF-8, no separators) has
at least `pow_difficulty` leading zero bits, with `pow_timestamp` within 300
seconds of the proxy clock. `pow_nonce` is chosen by the sender and must be 1
to 64 printable ASCII characters.

The difficulty is 0 (any proof of work is accepted) during normal operation
and rises while an invoice or the whole proxy is under attack:

```
difficulty = min(MAX_POW_DIFFICULTY, max(d_rate, d_global))
```

- `d_rate` depends on the recent calls for the invoice and `d_global` on the
  recent calls across all invoices
- recent calls are counted with an exponential decay with time constant
  `POW_WINDOW_SECS`, so the count approximates the number of calls in the last
  `POW_WINDOW_SECS` seconds, with older calls weighing less
- each term is 0 while its count is below its threshold, is 1 at the
  threshold and rises by 1 bit for each further step:
  `floor((count - threshold) / step) + 1`
- each term rises instantly and decreases only once its current value has
  been in effect for at least `POW_HOLD_SECS`
- only the `consignment.post` calls that create a transfer are counted, as
  they have already paid the difficulty in effect (rejected calls and
  idempotent re-posts are not, nor are `invoice.check` calls)

The current difficulty is reported by `invoice.check` and, when a proof of
work is insufficient, in the `data` of the "invalid proof of work" error, so
the sender can compute a new one and retry. The difficulty state is kept in
memory and resets when the proxy restarts. The proof of work can be disabled
by setting `MAX_POW_DIFFICULTY` to 0, e.g. on a private proxy hosting only
private invoices.

### Data retention

- invoice data (reservation, transfers, including the records of deleted ones,
  consignments and media) is never deleted before the invoice expiration;
  after it, it is deleted once no transfer is pending (neither retrieved nor
  deleted) or, at the latest, after `RETENTION_GRACE_SECS`
- `transfer.retrieved` deletes the consignment and media of a transfer right
  away, keeping its metadata so that identical re-posts are still recognized
- the signed TXs of an operation not ACKed by all its recipients (which can
  no longer be released) are deleted at the operation expiration, while the
  rest of the operation data (ACK values, signatures and released signed TXs)
  is kept for `RETENTION_GRACE_SECS` after the expiration, regardless of
  `ack.get` calls, so that the sender can retrieve the ACKs and recipients can
  still retrieve a released signed TX by posting their ACK again

## Running the app

### Locally

```sh
# install dependencies
npm install

# run in dev mode on port 3000
npm run dev

# generate production build
npm run build

# run generated content in dist folder on port 3000
npm run start
```

### In docker

```sh
docker run -d \
  -v /host/path/to/data:/home/node/.rgb-proxy-server \
  ghcr.io/rgb-tools/rgb-proxy-server
```

The container runs as the `node` user (uid/gid `1000`), so `$HOME` is
`/home/node` and the default data directory is `/home/node/.rgb-proxy-server`.
The mount path must be owned by uid/gid `1000`. To mount the volume elsewhere,
set `APP_DATA` to its path inside the container.

### Data

Stored under `$HOME/.rgb-proxy-server` by default. Override with `APP_DATA`.

## Configuration

Environment variables (see `.env-sample`):

| Variable               | Default               | Description                                                                                                                          |
| ---------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `APP_DATA`             | `~/.rgb-proxy-server` | Data directory                                                                                                                       |
| `MAX_EXPIRY_SECS`      | `2592000` (30 days)   | Max allowed `expires_at` offset                                                                                                      |
| `MAX_QUOTA`            | `100`                 | Max number of transfers an invoice can be reserved for                                                                               |
| `MAX_UPLOAD_BYTES`     | `104857600` (100 MiB) | Max consignment/media upload size (`max_file_size`)                                                                                  |
| `MAX_SIGNED_TX_SIZE`   | `153600` (150 KiB)    | Max per-transfer signed TX in `ack.prepare`, measured as the length of the base64 `signed_tx` string (`max_signed_tx_size`)          |
| `MAX_TRANSFERS`        | `1000`                | Max transfers per `ack.prepare` operation (`max_transfers`)                                                                          |
| `RETENTION_GRACE_SECS` | `86400` (1 day)       | Time data is kept after its expiration (max for pending transfers, always for operation data: ACKs, signatures, released signed TXs) |
| `MAX_POW_DIFFICULTY`   | `24`                  | Max proof of work difficulty (leading zero bits) required on `consignment.post`, `0` disables the proof of work                      |
| `POW_RATE_THRESHOLD`   | `10`                  | Recent `consignment.post` calls for an invoice at which its difficulty becomes 1                                                     |
| `POW_RATE_STEP`        | `2`                   | Further recent calls for an invoice for each additional bit                                                                          |
| `POW_GLOBAL_THRESHOLD` | `1000`                | Recent `consignment.post` calls across all invoices at which the difficulty of every invoice becomes 1                               |
| `POW_GLOBAL_STEP`      | `50`                  | Further recent calls across all invoices for each additional bit                                                                     |
| `POW_WINDOW_SECS`      | `3600` (1 hour)       | Time constant of the decay of the call counts (calls are counted over about this window)                                             |
| `POW_HOLD_SECS`        | `600` (10 minutes)    | Min time a difficulty stays in effect before it can decrease                                                                         |
| `PROXY_AUTH_PUBKEYS`   | _(none)_              | Comma-separated Ed25519 pubkeys (hex); when set, `invoice.prepare` and `ack.prepare` require a valid signature                       |

With the default proof of work settings, the difficulty of an invoice starts
rising after about 10 transfers in an hour and reaches 24 bits at about 56,
while the difficulty of all invoices starts rising after about 1000 transfers
in an hour across the proxy and reaches 24 bits at about 2150.

## API endpoints

All methods are invoked via `POST /json-rpc` (JSON-RPC 2.0). File uploads
(`consignment.post`, `media.post`) use `multipart/form-data` with a `file`
field and the params either as `params[<name>]` fields or as a single
JSON-encoded `params` field, which must precede the file. All numbers
(timestamps, sizes, quotas, difficulties), except `uptime` in `server.info`,
are carried as decimal strings.

| Method               | Caller → proxy        | Params → result                                                                                                                                                                                                       |
| -------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `server.info`        | any → any             | → `protocol_version`, `version`, `uptime`, `current_time`, `max_expiry_secs`, `max_quota`, `max_pow_difficulty`, `retention_grace_secs`, `max_file_size`, `max_signed_tx_size`, `max_transfers`                       |
| `invoice.prepare`    | recipient → recipient | `invoice_id`, `expires_at`, `recipient_pk`, `quota` (optional, default `1`), `signature` (proxy auth only) → `true` (reserved) / `false` (identical reservation)                                                      |
| `invoice.check`      | sender → recipient    | `invoice_ids` → `{invoice_id: {status: "unknown" \| "available" \| "full", pow_difficulty}}`                                                                                                                          |
| `consignment.post`   | sender → recipient    | `invoice_id`, `transfer_id`, `sender_transport_endpoint`, `sender_pk`, `consignment_hash`, `batch`, `file_size`, `signature`, `pow_timestamp`, `pow_nonce` + `file` → `true` (created) / `false` (identical transfer) |
| `consignment.get`    | recipient → recipient | `transfer_id` → `consignment` (base64), `sender_transport_endpoint`, `sender_pk`, `consignment_hash`, `batch`                                                                                                         |
| `media.post`         | sender → recipient    | `transfer_id`, `media_id`, `file_size`, `signature` + `file` → `true` (stored) / `false` (identical file)                                                                                                             |
| `media.get`          | recipient → recipient | `transfer_id`, `media_id` → media (base64)                                                                                                                                                                            |
| `transfer.list`      | recipient → recipient | `invoice_id`, `timestamp`, `signature` → `{transfer_id: "pending" \| "retrieved"}` (deleted transfers are not listed)                                                                                                 |
| `transfer.retrieved` | recipient → recipient | `transfer_id`, `signature` → `true` (data deleted) / `false` (already retrieved or deleted)                                                                                                                           |
| `transfer.delete`    | recipient → recipient | `transfer_id`, `signature` → `true` (deleted, quota slot freed) / `false` (already deleted)                                                                                                                           |
| `ack.prepare`        | sender → sender       | `transfer_data` (`{transfer_id: {recipient_pk, consignment_hash, signed_tx}}`), `expires_at`, `signed_tx_hash`, `sender_pk`, `signature` (proxy auth only) → `true` (registered) / `false` (identical operation)      |
| `ack.post`           | recipient → sender    | `transfer_id`, `ack` (bool), `signature` → `result`, `sender_pk` and `signed_tx_hash` (on ACK), `signed_tx` (once all the transfers of the operation have been ACKed), `expires_at` (operation expiration)            |
| `ack.get`            | sender → sender       | `transfer_ids`, `timestamp`, `signature` → `acks` (`{transfer_id: bool}`), `signatures` (`{transfer_id: signature}`); transfers not responded to yet are left out; doesn't trigger data deletion                      |
| `ack.clean`          | sender → sender       | `transfer_ids` (all the operation's), `signature` → `true` (signed TXs removed) / `false` (none left); refused once every transfer has been ACKed                                                                     |

Call `server.info` first to read `protocol_version`, `current_time` and the
limits.

## Errors

Errors are returned as `{"code": <code>, "message": "<message>", "data": ...}`.

| Code   | Message                         | Notes                                                                                                                                                             |
| ------ | ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-100` | Cannot change                   | `data.fields` lists the fields that differ from the stored ones                                                                                                   |
| `-101` | Invoice not reserved            | `consignment.post`, `transfer.list`                                                                                                                               |
| `-102` | Transfer ID in use              | `ack.prepare`: a transfer ID belongs to another operation                                                                                                         |
| `-104` | Operation not found             | `ack.post`, `ack.get`, `ack.clean`                                                                                                                                |
| `-105` | Operation expired               | `ack.post`                                                                                                                                                        |
| `-107` | Already acked                   | `ack.clean` once every transfer has been ACKed                                                                                                                    |
| `-108` | File too large                  | upload whose `file_size` exceeds `MAX_UPLOAD_BYTES`                                                                                                               |
| `-109` | Too many transfers              | `ack.prepare` with more than `MAX_TRANSFERS` transfers                                                                                                            |
| `-110` | Signed TX too large             | `ack.prepare` with a `signed_tx` longer than `MAX_SIGNED_TX_SIZE`, or a too big body                                                                              |
| `-111` | Invoice expired                 | `consignment.post`                                                                                                                                                |
| `-112` | Invoice quota exceeded          | `consignment.post`                                                                                                                                                |
| `-113` | Transfer ID deleted             | `consignment.post` for a transfer deleted via `transfer.delete`                                                                                                   |
| `-114` | Invalid proof of work           | `consignment.post`, `data.pow_difficulty` is the difficulty currently required                                                                                    |
| `-200` | Invalid                         | `data.fields` lists the invalid fields (including an out of window `timestamp`, a `file_size` not matching the uploaded file and a `file` sent before the params) |
| `-300` | Missing                         | `data.fields` lists the missing fields, reported before the invalid ones                                                                                          |
| `-301` | Missing file                    | upload with no `file`                                                                                                                                             |
| `-400` | Consignment not found           | `consignment.get`                                                                                                                                                 |
| `-401` | Media not found                 | `media.get`                                                                                                                                                       |
| `-402` | Transfer not found              | `media.post`, `transfer.retrieved`, `transfer.delete`                                                                                                             |
| `-403` | Transfer data retrieved         | `consignment.get`, `media.get`, `media.post` after `transfer.retrieved`                                                                                           |
| `-501` | Invalid proxy auth signature    | `invoice.prepare`, `ack.prepare`                                                                                                                                  |
| `-502` | Invalid endpoint auth signature | `consignment.post`, `media.post`, `transfer.*`, `ack.get`, `ack.clean`                                                                                            |
| `-503` | Invalid content signature       | `ack.post`                                                                                                                                                        |

`consignment.post` processes a call in this order: missing and invalid
parameters; identical re-post (returns `false`, ignoring the proof of work);
invoice reserved, invoice not expired, transfer ID derivation (`invalid`
`transfer_id`), signature, transfer ID not deleted, unchanged data of an
existing transfer; invoice quota; proof of work (only if the difficulty is
greater than 0).

`transfer.list` reports "invoice not reserved" and `transfer.retrieved` /
`transfer.delete` report "transfer not found" before verifying the signature.

## Signed messages

Signatures are Ed25519, hex-encoded, over the SHA-256 digest of the UTF-8
bytes of the listed fields, concatenated in order with no separators.

| Method               | Signer                                               | Message fields                                                                                                        |
| -------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `invoice.prepare`    | proxy auth key (only if `PROXY_AUTH_PUBKEYS` is set) | `invoice_id`, `expires_at`, `recipient_pk`, `quota` (`1` if omitted)                                                  |
| `consignment.post`   | sender (`sender_pk`)                                 | `transfer_id`, `consignment_hash`, `blob_hash`                                                                        |
| `media.post`         | sender (`sender_pk` from `consignment.post`)         | `transfer_id`, `media_id`, `blob_hash`                                                                                |
| `transfer.list`      | recipient (`recipient_pk` from `invoice.prepare`)    | `invoice_id`, `timestamp`                                                                                             |
| `transfer.retrieved` | recipient (`recipient_pk` from `invoice.prepare`)    | `transfer_id`, `retrieved`                                                                                            |
| `transfer.delete`    | recipient (`recipient_pk` from `invoice.prepare`)    | `transfer_id`, `delete`                                                                                               |
| `ack.prepare`        | proxy auth key (only if `PROXY_AUTH_PUBKEYS` is set) | `sender_pk`, `expires_at`, `signed_tx_hash`, then `transfer_id`, `recipient_pk`, `consignment_hash` for each transfer |
| `ack.post`           | recipient (`recipient_pk` from `ack.prepare`)        | `transfer_id`, `true` or `false`, `consignment_hash`                                                                  |
| `ack.get`            | sender (`sender_pk` from `ack.prepare`)              | all the requested `transfer_ids`, `timestamp`                                                                         |
| `ack.clean`          | sender (`sender_pk` from `ack.prepare`)              | all the operation's `transfer_ids`                                                                                    |

`blob_hash` is the hex-encoded SHA-256 of the uploaded file bytes (possibly
encrypted), computed by the proxy, so the signature binds the exact uploaded
file. `retrieved` and `delete` are literal strings.

Wherever multiple transfers are involved they are sorted lexicographically by
transfer ID, regardless of their order in the request. For `ack.get` this
means the message for `transfer_ids` = `["tidB", "tidA"]` and `timestamp` =
`"1782820543"` is `tidAtidB1782820543`. The `timestamp` of `ack.get` and
`transfer.list` must be within 300 seconds of the proxy clock.

## Example usage

### Reserve an invoice

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "invoice.prepare",
    "params": {
      "invoice_id": "<64-hex-invoice-id>",
      "expires_at": "1782820543",
      "recipient_pk": "<64-hex-ed25519-pubkey>",
      "quota": "5"
    }
  }' \
  localhost:3000/json-rpc
```

### Check an invoice

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "invoice.check",
    "params": {
      "invoice_ids": ["<64-hex-invoice-id>"]
    }
  }' \
  localhost:3000/json-rpc
```

Example result: `{"<64-hex-invoice-id>":{"status":"available","pow_difficulty":"0"}}`.

### Post a consignment

```sh
echo "consignment binary data" > consignment.rgb
curl -X POST -H 'Content-Type: multipart/form-data' \
  -F 'jsonrpc=2.0' -F 'id="3"' -F 'method=consignment.post' \
  -F 'params[invoice_id]=<64-hex-invoice-id>' \
  -F 'params[transfer_id]=<64-hex-transfer-id>' \
  -F 'params[sender_transport_endpoint]=rpc://sender.example.com/json-rpc' \
  -F 'params[sender_pk]=<64-hex-ed25519-pubkey>' \
  -F 'params[consignment_hash]=<64-hex-sha256-of-plaintext>' \
  -F 'params[batch]=false' \
  -F 'params[file_size]=24' \
  -F 'params[signature]=<128-hex-ed25519-signature>' \
  -F 'params[pow_timestamp]=1782820543' \
  -F 'params[pow_nonce]=0' \
  -F 'file=@consignment.rgb' \
  localhost:3000/json-rpc
```

### List the transfers of an invoice

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "4",
    "method": "transfer.list",
    "params": {
      "invoice_id": "<64-hex-invoice-id>",
      "timestamp": "1782820543",
      "signature": "<128-hex-ed25519-signature>"
    }
  }' \
  localhost:3000/json-rpc
```

### Prepare the ACK data (sender → sender proxy)

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "5",
    "method": "ack.prepare",
    "params": {
      "transfer_data": {
        "<64-hex-transfer-id>": {
          "recipient_pk": "<64-hex-ed25519-pubkey>",
          "consignment_hash": "<64-hex-sha256-of-plaintext>",
          "signed_tx": "<base64-encrypted-signed-tx>"
        }
      },
      "expires_at": "1782820543",
      "signed_tx_hash": "<64-hex-sha256-of-signed-tx>",
      "sender_pk": "<64-hex-ed25519-pubkey>"
    }
  }' \
  localhost:3000/json-rpc
```

When `PROXY_AUTH_PUBKEYS` is set, a `signature` by one of the proxy auth keys
is also required.

### Post a signed ACK (recipient → sender proxy)

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "6",
    "method": "ack.post",
    "params": {
      "transfer_id": "<64-hex-transfer-id>",
      "ack": true,
      "signature": "<128-hex-ed25519-signature>"
    }
  }' \
  localhost:3000/json-rpc
```

The response to a valid ACK includes `sender_pk` and `signed_tx_hash`, plus
`signed_tx` once all the transfers of the operation have been ACKed.

### Mark a transfer as retrieved

```sh
curl -X POST -H 'Content-Type: application/json' \
  -d '{
    "jsonrpc": "2.0",
    "id": "7",
    "method": "transfer.retrieved",
    "params": {
      "transfer_id": "<64-hex-transfer-id>",
      "signature": "<128-hex-ed25519-signature>"
    }
  }' \
  localhost:3000/json-rpc
```

## Testing

```sh
npm install
npm run test
```

## Formatting and linting

```sh
npm run format
npm run lint
npm run lint:fix
```

This project was originally implemented in
[grunch/rgb-proxy-server](https://github.com/grunch/rgb-proxy-server).
