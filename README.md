# Kosmos Store Catalog

Signed discovery metadata for Kosmos Manager. The Store catalog can advertise
Kosmos packages and external apps, but installation authority remains in the
separately signed Package Index.

Production trust:

- key id: `kosmos-store-2026`
- Ed25519 public key: `it14mzPjoqdgaHXdCDIjCoUgGXf/f5izJrGRUuk3o/A=`
- stable URL: `https://github.com/makekosmos/store/releases/latest/download/catalog.envelope.json`

Edit `catalog.json`, increment `sequence`, then run the `Publish catalog`
workflow. CI rejects an existing `catalog-N` release and requires the new
sequence to be greater than every prior immutable catalog release before it
uses the signing secret. The private key exists only in the
`STORE_SIGNING_KEY` repository secret. The checked-in
`catalog.envelope.json` intentionally remains the previous signed envelope
until that CI secret is available; do not generate a production signature
locally.

Key rotation changes the `key_id`, public-key allowlist, and release
documentation together. Historical envelopes remain verifiable under their
original key; never overwrite a published tag.

## Secret-free validation

Pull requests run a validator that checks catalog schema, unique identities,
valid package/external distributions, HTTPS URLs, validity windows, replacement
references/cycles, and the committed envelope signature without accessing
`STORE_SIGNING_KEY`:

```powershell
node scripts/validate-catalog.mjs
node --test scripts/validate-catalog.test.mjs
```

The dry-run path exercises ephemeral Ed25519 signing without publishing or
using production credentials:

```powershell
node scripts/dry-run.mjs
```

After signing, publication operators require the envelope payload to match the
catalog bytes with:

```powershell
node scripts/validate-catalog.mjs --strict-envelope
```
