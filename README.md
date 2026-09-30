# pqcota-inventory

The inventory stage of the pqcota platform: accumulate what discovery observed and read it back.

It loads collector results into an append-only history, normalizes them into findings, and serves read-only views over what has accumulated. It is one of five repositories that make up [pqcota](https://github.com/randyinthedev-hash/pqcota): `pqcota-common`, `pqcota-inventory`, `pqcota-discovery`, `pqcota-provisioning`, and the integration repository `pqcota` (demo, examples, release bundles, contributing guide).

## What is here

| Path | What |
|---|---|
| `pkg/inventory/` | the library: `history` (append-only store, in-memory and Postgres), `normalize` (raw capture to derived findings), `ingest`, `resultio`, `declaration`, and the views |
| `inventory/cmd/` | the commands: `pqcota-ingest`, `pqcota-inventory`, `pqcota-discover-view`, `pqcota-cbom-ingest`, `pqcota-declare`, `pqcota-declare-attribution`, `pqcota-profile`, `pqcota-prune` |
| `examples/` | runnable examples (`inventory/`: views, declared attribution, CBOM intake) and the shared sample results in `examples/data/` that the discovery examples read too |
| `inventory/README.md` | what the stage does and how to use it |

## Depends on

`pqcota-common` only. Discovery and provisioning both depend on this module, so it imports neither.

## Build and test

```bash
make            # every check of this repository
go test ./...   # unit tests only
```

Until the modules are tagged, `go.mod` points at the sibling repositories with `replace` directives (`../pqcota-common` and so on), so clone the repositories side by side. Remove the `replace` lines and raise the `require` versions once the tags exist.

## Contributing · security · license

Contributing and security reporting are described in the [pqcota repository](https://github.com/randyinthedev-hash/pqcota). Licensed under [Apache-2.0](https://github.com/randyinthedev-hash/pqcota/blob/main/LICENSE).
