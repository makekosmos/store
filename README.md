# Kosmos Store Catalog

Signed discovery metadata for Kosmos Manager. The Store catalog can advertise
Kosmos packages and external apps, but installation authority remains in the
separately signed Package Index.

Production trust:

- key id: `kosmos-store-2026`
- Ed25519 public key: `it14mzPjoqdgaHXdCDIjCoUgGXf/f5izJrGRUuk3o/A=`
- stable URL: `https://github.com/makekosmos/store/releases/latest/download/catalog.envelope.json`

Edit `catalog.json`, increment `sequence`, then run the `Publish catalog`
workflow. The private key exists only in the `STORE_SIGNING_KEY` repository
secret. The checked-in `catalog.envelope.json` intentionally remains the
previous signed envelope until that CI secret is available; do not generate a
production signature locally.

## Secret-free validation

Pull requests run a validator that checks catalog schema, unique identities,
valid package/external distributions, HTTPS URLs, validity windows, and the
committed envelope shape without accessing `STORE_SIGNING_KEY`:

```powershell
node scripts/validate-catalog.mjs
```

After signing, publication operators can additionally require the envelope
payload to match the checked-in catalog bytes with
`node scripts/validate-catalog.mjs --strict-envelope`.
