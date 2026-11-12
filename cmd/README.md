English · [한국어](README.ko.md)

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
| `PQCOTA_AUTO_DDL` | if `0`, the history schema is not created; if it is absent, the command stops with an error. The metadata and provisioning-record tables are still created. It prevents a new empty table from being created and written to when the connection points at the wrong place |

> **If `PQCOTA_DSN` is given but the store cannot be opened, it stops.** v0.1.x fell back to in-memory and carried on,
> and then the screen printed success while the data vanished with the process. Giving a DSN is a request for persistence.

The result of an unregistered node is refused and not stored; a **refusal entry** (node, collector, reason, content hash) is kept, in the database if one is configured.

> **How the current implementation builds a node's latest snapshot.** For each node that appears in one load, it makes the
> latest snapshot from the results in **that load only**. It does not carry over findings or edges from the node's earlier
> snapshot. A node that does not appear in the load keeps its latest snapshot.
>
> So if you load only some of a node's results (for example only the JVM result), the assets and connections you did not
> submit drop out of the latest view, and a comparison (`pqcota-inventory -diff`) can show them as `removed`. A layer that was
> not submitted is not always shown as a gap today, so **do not read this as evidence that an asset was removed or that a
> connection does not exist.** The earlier snapshots stay in the history and can still be read with `-snapshot`.
>
> To keep the latest view complete, put every result you want it to reflect for a node in the same load:
>
> ```
> # the results of several nodes (OpenSSL, JVM, network) gathered in one directory and loaded at once
> ls results/
> pay-app-jca.jsonl  pay-app-net.json  pay-app-openssl.json  web-gw-net.json  web-gw-openssl.json ...
> pqcota-ingest results/
> ```

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

> **The note under `pqcota-ingest` applies here too.** An external CBOM loaded under a node that pqcota also observes at runtime
> becomes that node's latest snapshot, with only the CBOM's findings in it. The runtime snapshots stay in the history, but the latest
> view and the provisioning before-capture read the CBOM snapshot. A comparison that takes the latest snapshot compares against
> the CBOM snapshot; a comparison between two earlier snapshots you name is not affected. A plan that names a
> runtime snapshot explicitly still resolves to it. To keep a CBOM out of the runtime view altogether, load it as
> source evidence (`--source-evidence`, below).

> **Injecting from a CI pipeline**: you can pipe CBOMkit's output straight in without an intermediate file (GitHub Actions, GitLab CI and so on):
> ```bash
> cbomkit scan ./repo | pqcota-cbom-ingest - cmdb://payment-gw
> ```
> CI knows what it is building, so it pins `target-node-id` here (without an anchor it is routed to the scope decision, see [pqcota-discovery README](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.md)).

### Source evidence: `pqcota-cbom-ingest --source-evidence`

```
pqcota-cbom-ingest <cbom.json | -> [target-node-id] --source-evidence
                   [--preset <id>] [--source-map <file>] [--allow-unmatched-rules] [--dry-run] [--json]
```

With `--source-evidence` the CBOM is **not** turned into a snapshot. It is kept as **source evidence**: the crypto items the CBOM
reports and the source locations it gives for them, for review. Nothing in the runtime view, the history or the provisioning
before-capture changes. Without the flag the command behaves as described above.

What is stored, in one transaction for the organization: the CBOM exactly as received, the mapping files used (below), the
conversion result, and a receipt. Receiving the same CBOM again with the same mapping adds only a receipt. Read it back with
[`pqcota-source-evidence`](#pqcota-source-evidence).

| Option | What it does |
|---|---|
| `[target-node-id]` | optional. Recorded as given in the receipt; it is **not** checked against the scope master |
| `--dry-run` | converts and prints the preview, writes nothing and does not open the database |
| `--json` | machine-readable output, `format: "pqcota-source-evidence/v1"`, `kind: "ingest"`. It says whether the result was stored, where (`storeKind`, `persistent`) and, if refused, why (`refusals`) |
| `--preset <id>` | applies a built-in mapping (list them with `pqcota-source-evidence --presets`) |
| `--source-map <file>` | applies your own mapping file (at most 256 KiB) |
| `--allow-unmatched-rules` | accepts a mapping rule that matched nothing in this CBOM; the result simply has no locations from that rule |

**What it reads.** The standard CycloneDX fields of every `cryptographic-asset` component (name, asset type, OID, algorithm
properties, `evidence.occurrences`) are always read. Other components are only counted. `properties` are kept as the tool's own
values, never as a pqcota verdict. A location is shown as a **reported location for review**: the CBOM does not say whether it is a
call, a declaration or a comment, so neither does pqcota. Line and column numbers are shown as reported; they are turned into
1-based numbers only when the counting base is known. The standard `line` field does not state its base, so it is shown as
reported.

**Checked with real tool output.** The standard fields have been checked against the actual output of these tools:

| Tool | Input | What pqcota read | Through |
|---|---|---|---|
| CBOMkit (`cbomkit-action` v2.3.0) | a Java 21 example written for the check; CycloneDX 1.6 | `evidence.occurrences.location` and `line`, without a preset | pqcota v0.12.0: the location chosen in a plan stayed the same reference through approval and into the generation record, with and without a guide |
| CBOMkit (`cbomkit-action` v2.3.0) | a Python 3.13 example written for the check, using `pyca/cryptography` 50.0.2; CycloneDX 1.6 | `evidence.occurrences.location` and `line`, without a preset | pqcota v0.12.0: the location chosen in a plan stayed the same reference through review, signing and the generation record, without a guide |
| CryptoScan 1.5.0 | a C example written for the check (OpenSSL 3 EVP); CycloneDX 1.6 | `evidence.occurrences.location` and `line` (the tool's `symbol` is kept), without a preset | pqcota v0.12.0: the same, without a guide (no guide in the catalog fits this code) |

CBOMkit, Java example:

- The CBOM held 14 locations. Six calls had been marked in the example as expected locations, and all six were reported at exactly those lines.
- The paths and lines are kept as the tool reported them. The paths start with the directory the source was mounted at for the tool (`ws/`), and the counting base of the line is not stated, so it is shown as unknown.
- **Limits seen in this run:** a key generator whose algorithm name was passed in a variable was not reported, and a 256-bit AES-GCM key was reported as 128 bits. **Seen in an earlier run** of the same version on other code (2026-11-10): calls to the Bouncy Castle lightweight API (`MLKEMGenerator` and the like) were not reported.

CBOMkit, Python example:

- The consolidated CBOM held 6 locations in `evidence.occurrences`, all read without a preset. They pointed at 3 distinct source lines, all key-generation calls (AES-GCM key, RSA-3072 key, EC P-256 key).
- The location referenced in the plan was the RSA-3072 key generation at line 27, and that reference was kept through review, signing and the generation record.
- **Limits seen in this run:** the calls that encrypt, wrap the document key with RSA-OAEP, sign and hash were not reported for this example.

CryptoScan, C example:

- The CBOM held 3 locations. Two of the expected locations were reported at exactly their lines: the two key-generation calls, at the algorithm name strings `"RSA"` and `"P-256"`.
- **Limits seen in this run:** the OpenSSL EVP calls (AES-GCM encryption, RSA-OAEP key wrapping, ECDSA signing) were not reported, and an `#include <openssl/rsa.h>` line was reported as a location. The same was seen on 2026-11-10 with the same version and input.
- Only C was checked. C++ was not.

Each row is what one tool version reported for one example. It does not describe the tool's detection range.

**Mappings.** Some tools put source locations in `properties` instead of `evidence.occurrences`. A mapping tells pqcota where to
read them. Two presets come built in:

| Preset | Checked against | Reads |
|---|---|---|
| `cdxgen-dotnet-sourcelocation@1` | cdxgen 13.7.0, .NET 8 project | `cdx:crypto:sourceLocation` (`path:line:column`, several per component) |
| `dosai-cyclonedx-location@1` | dosai 5.0.0.0 CycloneDX output, .NET 8 project | `dosai:location` on `cryptographic-asset` components |

A preset is checked only against the tool version listed. In both, lines count from 1 and the column's base and unit are
`unknown`, so columns are shown as reported. For another tool, write a mapping file:

```json
{
  "format": "pqcota-source-map/v1",
  "id": "my-scanner",
  "revision": "1",
  "rules": [
    {
      "id": "source-location",
      "componentTypes": ["cryptographic-asset"],
      "locations": {
        "from": "component",
        "combined": {"property": "my:sourceLocation", "each": true, "parser": "path:line:column"},
        "lineBase": 1,
        "columnBase": "unknown",
        "columnUnit": "unknown"
      }
    }
  ]
}
```

- `combined` reads one property whose value holds a whole location. The parsers are `path:line` and `path:line:column`. Numbers
  are taken from the right, so `C:\src\a.cs:12:5` works. Without `"each": true`, several values in one component are an error.
- Instead of `combined`, `file` with optional `line` and `column` reads separate values. Each is `{"property": "<name>"}` or
  `{"pointer": "<JSON Pointer inside the component>"}`. Add `"array": "<pointer>"` to read one location per element of an array.
- `lineBase` is required: `0`, `1` or `"unknown"`. A column needs `columnBase` and `columnUnit` (`byte`, `utf16`, `codepoint` or
  `unknown`). Write `"unknown"` when you have not checked it. The value is then shown as reported, not converted.
- Unknown keys and other `format` versions are refused. Change `revision` whenever you change the file.

**When it refuses.** A mapping you name must convert without errors. Two values where one was expected, a value that does not fit
the parser, a missing field, or an invalid line or column all mean **nothing is stored** (exit code 1, the preview also exits 1). A
rule that matched no component is refused too, unless you pass `--allow-unmatched-rules`. A malformed mapping file or an unknown
preset stops the command before the CBOM is converted (exit code 2). Options it does not know also exit with 2, so a mistyped flag never
falls back to writing a snapshot.

**Size limits.** The CBOM may be at most 32 MiB and a mapping file at most 256 KiB. A larger file is not read to the end: a CBOM
over the limit exits with 1, a mapping file over the limit with 2 (like any other unusable mapping). Nothing is stored either way.

```bash
# look first, then store
pqcota-cbom-ingest cbom.json --source-evidence --preset cdxgen-dotnet-sourcelocation --dry-run
pqcota-cbom-ingest cbom.json web-01 --source-evidence --preset cdxgen-dotnet-sourcelocation
```

`env PQCOTA_DSN` stores it in Postgres. Without it the result is kept in memory and is gone when the command ends; the output says
which.

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

The **direction convention of `-diff`: first argument = past, second = latest** (`added` = present only in the second, `removed` = present only in the first). Giving them in reverse time order makes the direction read backwards, so **it warns if they are reversed.** The finding id is a hash of (node, name, runtime, fork, and for OpenSSL the library path when the input has it), so **even when the version changes it is caught as a `changed` of the same asset**, and two installations with the same file name on one node stay two assets. If the rulesets differ, it warns that a difference in derived values may be a recomputation result.

**Snapshots accumulate only at change points.** Observing the same state again does not create a new snapshot and leaves only an **observation record** (lightweight), so the `obs` and `observed` columns of `-history` show "how many times and until when that state was re-confirmed". So the heavy storage grows **only as many times as there are changes**, yet the evidence that "it was scanned every time" is kept.

### `pqcota-source-evidence`

```
pqcota-source-evidence [--limit N] [--json]
pqcota-source-evidence --id <interpretation-id> [--json]
pqcota-source-evidence --input <sha256> --out <file>
pqcota-source-evidence --map <sha256> --out <file>
pqcota-source-evidence --presets [--json]
```

Reads the source evidence stored by `pqcota-cbom-ingest --source-evidence`. Read-only: it does not create tables, so an account
that can only `SELECT` is enough. `env PQCOTA_DSN` is required, except for `--presets`.

| Flag | What it does |
|---|---|
| (none) | lists stored conversions, newest first: CycloneDX version, the tool the CBOM names, the mapping used, item and location counts, how often it was received and the target nodes given (user-specified). Receipts are counted up to the latest 100 per conversion; beyond that it says "more than 100" and the target nodes are those of the latest 100 |
| `--id <id>` | one conversion: its latest 100 receipts, then every item and its reported locations. If there are older receipts it says so (in `--json`, `receiptsTruncated: true`). The same location reported more than once is shown on one line, and every original pointer is listed under it |
| `--input <sha256> --out <file>` | writes the CBOM exactly as received to a new file. It checks the hash first, does not overwrite an existing file, and never prints the bytes to the terminal |
| `--map <sha256> --out <file>` | the same for a mapping file used in a conversion |
| `--presets` | the built-in mappings and what they were checked against |
| `--json` | `format: "pqcota-source-evidence/v1"`, `kind: "interpretations"`, `"interpretation"` or `"presets"`. The detail keeps every location separate and gives the on-screen grouping as `displayGroups` |

Paths, symbols and context come from the CBOM. They are shown as text with control characters escaped, and nothing is opened or run.
Another organization's evidence (`PQCOTA_ORG`) is not visible.

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
| `--dsn <postgres>` | if given, upserts into the inventory, under the organization named by `PQCOTA_ORG` (the default organization when it is unset). If not, it only shows the parse result |

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
- To **keep an external CBOM as source locations for review, apart from what runs** → **`pqcota-cbom-ingest --source-evidence`**, read back with **`pqcota-source-evidence`**.

> The logic lives in `pkg/inventory/` (the loading adapter `ingest`, view rendering, `RenderStore`, the machine metadata `MetaStore`, the hosts parser), including normalization and the history store, and these commands are thin entry points that assemble it.
