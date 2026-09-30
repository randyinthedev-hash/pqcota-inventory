# cmd/: the inventory entry points

The CLIs (Go binaries) of the inventory stage. They **load into the center** what the collectors observed, and **read back**, read-only, what has accumulated. They are sorted into five categories.

## ① Loading: accumulate the retrieved results into the history

**`pqcota-ingest` reads from one directory** the `CollectionResult` JSON files the collectors produced, and loads them through the scope gate → normalization → the append-only history. This is what makes the data the query commands below read.

Gathering the files into that directory is **the user's** job. In the demo, Ansible runs the [collectors](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md) on each node and retrieves the results to the controller.

### `pqcota-ingest`

```
pqcota-ingest [-scope-assets <csv>] <results-dir> [scope-master-file]
```

| Argument · option | What it does |
|---|---|
| `<results-dir>` | reads every `*.json` (a single object) and `*.jsonl` (one line = one result). **The format is decided by the content, not the extension.** The jvm attach path emits several JVMs per node as JSONL. If even one input cannot be decoded, it **stops without loading.** If only half went in, a missing asset would be indistinguishable from an asset that does not exist |
| `[scope-master-file]` | the node registration gate. If not given, the gate is skipped |
| `-scope-assets <csv>` | asset scope: keeps only the assets to go on managing within the registered nodes (below) |

| Environment variable | What it does |
|---|---|
| `PQCOTA_DSN` | the Postgres connection string ([format](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md#pqcota-hosts)). If absent there is only an in-memory summary: nothing is persisted |
| `PQCOTA_VERIFY_KEY` | public keys (comma separated). If present it verifies the result signatures and refuses a mismatch. The key pair is made by [`pqcota-keygen`](https://github.com/randyinthedev-hash/pqcota-common/blob/main/cmd/README.md#pqcota-keygen), and the matching private key is used **by the collector on the node** |
| `PQCOTA_REQUIRE_SIGNATURE` | if `1`, **loading does not start** when there is no key to verify with. If absent, verification is skipped but that count is reported separately as "signature unchecked". It is not put in the same place as a pass |
| `PQCOTA_ORG` | the organization this load belongs to (lowercase, digits and hyphens, 2–64 characters). If absent it is bound to `default`. **Every command that opens the store has to see the same value**: if the reading side and the writing side differ, the data is there but you cannot see it |
| `PQCOTA_REQUIRE_ORG` | if `1`, the store cannot be opened without an organization. `default` cannot be used as a name either (it is reserved). For deployments where several organizations share one store: once mixed they cannot be separated again, so it is blocked **at the point of opening** |
| `PQCOTA_AUTO_DDL` | if `0`, the schema is not created. If absent, it stops with an error. It prevents a new empty table from being created and written to when the connection points at the wrong place |

> **If `PQCOTA_DSN` is given but the store cannot be opened, it stops.** v0.1.x fell back to in-memory and carried on,
> and then the screen printed success while the data vanished with the process. Giving a DSN is a request for persistence.

The results of an unregistered node are not thrown away and remain as a **registration request**.

### `pqcota-declare-attribution`

```bash
pqcota-declare-attribution [--out <dir>] <attribution.csv>   # CSV: node_id,dst,app_key
pqcota-ingest <dir>                                          # load into the declaration lane
```

Network observation can find the app only if **the socket is alive at the moment of capture**. A connection that attaches
and drops quickly (a batch job, a health check, cron, SSH) falls outside that window, so `app_key` stays empty. It is the
blank that shows as `@?` on the query screen. The operator fills that blank with this command.

| | |
|---|---|
| `node_id` | the observing host (the edge's src) |
| `dst` | the peer, exactly as printed on the edge: it appears in `pqcota-inventory -snapshot`. **Do not write the port separately**: the contract defines `dst_addr` as `"ip:port"` so it is already there, and writing it in two places lets one go wrong without any warning |
| `app_key` | the app that opened this edge |

**A sample you can run as it is** is in [examples/inventory](../examples/inventory/README.md#pqcota-declare-attribution-a-person-writes-the-app-for-an-edge-the-observation-could-not-attribute) ([attribution.csv](../examples/inventory/attribution.csv)).

> **It does not edit the observation.** The declaration accumulates in its own lane (`detection_method=UNSPECIFIED`),
> and combining happens **on the screen at query time**. It fills **only the blanks** without overwriting an app the observation
> already caught, and what was filled is shown as `@app(declared)` together with how many there are.
>
> There are two reasons to keep them apart in storage. The signature covers `app_key`, so editing it would differ from what the
> collector signed, and recomputing from the original would differ from the stored value.

### Asset scope (`-scope-assets`)

Registering a node does not make **everything observed inside it** a managed target. If the system's default libraries, or a runtime that a package pulled in, get mixed in, the inventory drowns in noise. **The user declares** what to keep watching, and the tool enforces it.

```csv
action,runtime,lib,app_key,note
exclude,*,*,/usr/bin/python*,the package's python runtime — not a managed target
exclude,openssl,libcrypto.so.*,*,exclude this whole family
include,openssl,libcrypto.so.3,/opt/apps/payment-gw,an exception for the payment gateway only
```

- An empty cell and `*` both mean "all". Patterns are globs. With no rules, **everything is managed** (included by default).
- The decision: included by default → removed by `exclude` → put back by `include`. **`include` beats `exclude`**, so you can write "remove this whole family but keep this one".
- A shared `.so` has several apps using it, so a rule applies if **even one of them matches**.
- **Excluded is not "absent".** The load summary and the inventory view announce how many were removed. If things vanished without notice, the inventory would be lying that "there is no such asset".

## ② CBOM intake: import results produced by an external tool

For the runtimes a collector **observes directly**, source and build artifacts are **delegated, not scanned**. pqcota **receives** the standard CycloneDX that CBOMkit produced in the user's CI, and validates, normalizes and loads it. pqcota does not run CBOMkit. → [discovery/README ②](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.md)

### `pqcota-cbom-ingest`

```
pqcota-cbom-ingest <cbom.json | -> <target-node-id>
```

It receives, validates and loads a CycloneDX. A non-conforming one is refused and not stored.

| Argument | What it does |
|---|---|
| `<cbom.json>` | the CycloneDX file to receive. `-` means stdin (CI injection, below) |
| `<target-node-id>` | which node's asset to anchor that CBOM to |

If `env PQCOTA_DSN` is set it persists in Postgres, and if not it only prints an in-memory summary.

> **Refusal is deterministic validation, not judgement.** There is one reason for refusal today: a **non-conforming structure** (malformed JSON · not CycloneDX (`bomFormat`) · an unsupported `specVersion`). `ImportCBOM` puts signature verification as its first gate, but this command has no place to be given a key, so that gate does not stand, and the command says so on stderr every time it runs. Both are decided mechanically. Conversely, a missing `target_node_id` binding is **not a refusal**: it is routed to the scope decision, and an asset without `pqcota:` properties is **not a refusal** either: it is simply not parsed, with unknown strength. "Throw away what cannot be trusted, but never say something is absent because it was not seen."

`ImportCBOM` validates the structure and the anchor (the signature gate is not wired: see the note above). What passes converges into the same history as above, through the observation lane (`detection_method=source/artifact`). Adapter: `pkg/inventory/ingest`.

> **Injecting from a CI pipeline**: you can pipe CBOMkit's output straight in without an intermediate file (GitHub Actions, GitLab CI and so on):
> ```bash
> cbomkit scan ./repo | pqcota-cbom-ingest - cmdb://payment-gw
> ```
> CI knows what it is building, so it pins `target-node-id` here (without an anchor it is routed to the scope decision, see [pqcota-discovery README](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.md)).

## ③ Query: read what has accumulated, read-only

The key distinction is **file collation (volatile, local) vs a central store query (persistent, a separate process)**.

### `pqcota-discover-view`

```
pqcota-discover-view <results-dir> [nodes.json] [topology-out.dot]
```

| Argument | What it does |
|---|---|
| `<results-dir>` | collates the retrieved `CollectionResult` JSON files on the spot |
| `[nodes.json]` | maps observed IPs to node names (`10.0.0.9` → `node-c`) |
| `[topology-out.dot]` | writes the communication topology as DOT (colour = grade) |

It prints the discovered assets (OpenSSL, JCA) and the grade of each observed communication edge. **It does not use the store**: it is a volatile view.

### `pqcota-inventory`

```
pqcota-inventory [-history <node>] [-snapshot <id>] [-diff <past-id>,<latest-id>]
```

Run with no arguments it prints **the latest snapshot of every node + a grade tally**. The `▸` machine header (endpoint and profile) and `@` app labels (a shared `.so` shows several) are attached. `env PQCOTA_DSN` is required (it reads the append-only history and the machine metadata in Postgres).

| Flag | What it does |
|---|---|
| `-history <node>` | lists that node's snapshots **oldest first**: seq, load time, ruleset, findings and edges counts, gaps |
| `-snapshot <id>` | **detail of a single snapshot**: the asset table + that snapshot's **observed edges** (the cumulative view prints only totals, so they unfold only here) |
| `-diff <past-id>,<latest-id>` | the **changes** between two snapshots: `added`, `removed`, `changed` |

The **direction convention of `-diff`: first argument = past, second = latest** (`added` = present only in the second, `removed` = present only in the first). Giving them in reverse time order makes the direction read backwards, so **it warns if they are reversed.** The finding id is a hash of (node, name, runtime, fork), so **even when the version changes it is caught as a `changed` of the same asset.** If the rulesets differ, it warns that a difference in derived values may be a recomputation result.

**Snapshots accumulate only at change points.** Observing the same state again does not create a new snapshot and leaves only an **observation record** (lightweight), so the `obs` and `observed` columns of `-history` show "how many times and until when that state was re-confirmed". So the heavy storage grows **only as many times as there are changes**, yet the evidence that "it was scanned every time" is kept.

## ④ Retention policy: truncate old change points

### `pqcota-prune`

```
pqcota-prune [-older-than 90d] [-keep-last N] [-apply]
```

| Flag | What it does |
|---|---|
| `-older-than <duration>` | truncates change points older than this (e.g. `90d`, `720h`) |
| `-keep-last <N>` | keeps each node's most recent N change points |
| `-apply` | actually deletes. **Without it only the plan is shown** (dry-run by default) |

If you give both axes, the decision is **conservative** (only when both allow discarding). With no policy at all, it refuses.

Three invariants: **the latest is untouchable** (each node's latest is never deleted by any policy: it is the basis of the inventory view and of the provisioning before-capture), **no modification** (the remaining snapshots stay byte for byte), and **the fact of truncation is recorded** (`-history` announces it with a `⌫` line; without it a gap in the history would read as "not observed"). It is **deliberately separated** from the query commands. If a read tool also performed destructive actions, one mistake would erase the history.

## ⑤ Metadata · declaration import

Endpoints are filled by `pqcota-hosts --dsn` (pqcota-discovery), and profiles and declarations are filled by the two below. → [the collector and access-prep command map](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.md)

### `pqcota-profile`

```
pqcota-profile [--dsn <postgres>] <profiles.csv>
```

| Argument · option | What it does |
|---|---|
| `<profiles.csv>` | machine profiles (`display_name`, `environment`, `role`, `owner`, `location`, `labels`). The source is the CMDB |
| `--dsn <postgres>` | if given, upserts into the inventory. If not, it only shows the parse result |

It is **human-facing metadata** kept separate from identity. It fills the `▸` header of the view.

### `pqcota-declare`

```
pqcota-declare [--out <dir>] <declaration.csv>
```

| Argument · option | What it does |
|---|---|
| `<declaration.csv>` | the user's declared inventory (`node_id`, `crypto_runtime`, `component`) |
| `--out <dir>` | the output directory for `CollectionResult` JSON (default `declared-results`) |

**It is not an observation.** `detection_method` goes out empty. If you load the JSON it produces with `pqcota-ingest <dir>` (①), it becomes the baseline for a comparison.

## When to use what
- To **collate the retrieved result files once and look at them on the spot** → **`pqcota-discover-view`** (no store needed, volatile).
- To **query centrally the cumulative inventory that several nodes built up over time** (including endpoints, profiles and app labels) → **`pqcota-inventory`** (Postgres).

> The logic lives in `pkg/inventory/` (the loading adapter `ingest`, view rendering, `RenderStore`, the machine metadata `MetaStore`, the hosts parser), including normalization and the history store, and these commands are thin entry points that assemble it.
