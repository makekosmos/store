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
uses the signing secret. Publication checks the release and tag before the key
is loaded, then signs and verifies the exact reviewed catalog bytes. The private key exists only in the
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
bun run check
```

The dry-run path exercises ephemeral Ed25519 signing without publishing or
using production credentials:

```powershell
node scripts/dry-run.mjs
```

The dry-run creates an in-memory ephemeral Ed25519 key, validates the complete
catalog and envelope, and never writes a release or uses `STORE_SIGNING_KEY`.

`bun install --frozen-lockfile` installs the repository hooks automatically.
Pre-commit validates staged catalog, workflow, hook, documentation, and toolchain
metadata changes; pre-push and CI run the aggregate `bun run check` contract.
Store has no runtime or development dependencies, so Bun intentionally omits an
empty lockfile and dependency audit is not applicable. Frozen install, signature,
provenance, secret scan, and immutable-release gates remain required.

After signing, publication operators require the envelope payload to match the
catalog bytes with:

```powershell
node scripts/validate-catalog.mjs --strict-envelope
```

Local `check:signature` uses `--candidate`: it verifies the historical envelope
signature and permits changed source bytes only at a greater Store sequence.
Exact already-signed bytes also pass. Production publication and the signing
dry-run keep strict byte-equality validation.

Store and Package Index have independent catalog sequences. Store catalog 14
reconciles discovery with the already-published Package Index catalog 13;
it does not rewrite that release or its BOM. The reconciliation fixture records
both sequences and the downloaded Package Index catalog/BOM hashes.

## Key rotation

Rotate the signing key as a coordinated change: add the new public key and
`key_id` to the validator allowlist, update the production secret, document the
new trust key here, and publish a new monotonic `catalog-N` release. Keep old
keys in the allowlist while historical envelopes are still served, and never
overwrite an existing release or tag. Test the rotation with the secret-free
dry-run before production signing.
