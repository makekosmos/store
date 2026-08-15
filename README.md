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
secret.
