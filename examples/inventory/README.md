English · [한국어](README.ko.md)

# examples/inventory: the read-only inventory view

```bash
./examples/inventory/run.sh
```

## What happens

### `pqcota-discover-view`: collate the results → assets + apps + grades

> The sample includes one **Windows CNG node (`node-d`)**. It sits beside the three Linux collectors,
> so you can see here that the view draws in the same place even as runtimes are added. That node's line carries the provider count,
> the algorithm count and a PQC summary (`native (signature only — no KEM observed)`).

It gathers the `CollectionResult` JSON files in [`../data/results`](../data) and shows the **discovered assets** and the **grade of each observed communication edge** (file collation, volatile, no storage needed). It does not compare or judge (reconcile).

Expected output (the gist):
```
──────── ① discovered assets (per node) ────────
  node-a
    • OpenSSL  libssl.so.3 3.0.13 (OpenSSL) [EVIDENCE_STRENGTH_CONFIRMED]
  node-b
    • JCA provider chain: SUN,SunJCE,BC [EVIDENCE_STRENGTH_CONFIRMED]

──────── ② observed edges + quantum-resistance grade ────────
  🟢 node-a      → node-b             TLS   X25519MLKEM768 [fips-standard]
  🔴 node-a      → node-c             TLS   x25519
  🟢 node-a      → node-b             SSH   sntrup761x25519-sha512@openssh.com [experimental]

  grade totals: 🟢 PQC 2 · 🔴 classical 1 · ⚪ unknown 0
```
- **Grade**: 🟢 PQC/hybrid · 🔴 classical = quantum-vulnerable · ⚪ unknown. A PQC group also carries its maturity (`fips-standard`/`draft`/`experimental`/`broken`).
- **Joining IP to node**: `nodes.json` maps `10.0.0.9` → `node-c` (the edge's `dstAddr` is shown by name).
- A topology **DOT** file is also generated (colour = grade): render it to SVG with `dot -Tsvg`.

> App labels (`@app`) and the endpoint and profile header are shown together in the **central persistent view** (`pqcota-inventory`, Postgres). This file-collation view centres on assets and edges.

### `pqcota-declare-attribution`: a person writes the app for an edge the observation could not attribute

Network observation can find the app that opened a connection only if **the socket is alive at the moment of capture**. A connection that attaches
and drops quickly (a batch job, a health check, cron, SSH) falls outside that window, so `app_key` stays empty and the query screen
shows `@?`. **That means "we could not tell which app", not "there is no app"**, and the operator fills
that blank with this command.

The input is a single file, [`attribution.csv`](attribution.csv).

```csv
node_id,dst,app_key
node-a,10.0.0.9:443,nightly-sync.service
```

| Column | What |
|---|---|
| `node_id` | the observing host, that is, the edge's src |
| `dst` | the peer. Use the address exactly as printed on the edge. The contract defines `dst_addr` as `"ip:port"`, so the port is already in it and **you do not write the port separately** |
| `app_key` | the app that opened this edge |

If the first cell of the first line is `node_id`, it is treated as a header and skipped. If any of the three values is empty, it
**stops** and names the line number. Pointing at an app without knowing which edge it belongs to would change what gets acted on.

**Copy `dst` from the `pqcota-inventory -snapshot` screen.** In the sample above, that edge appears in this file-collation
view as `node-a → node-c`, but that is `nodes.json` swapping the IP for a name so it reads well,
and the value actually carried on the edge is `10.0.0.9:443`. What a declaration has to match is the carried value. When the peer
is joined to a node of the scope master and the address is empty, write that `node_id` instead.

**The key is just two things: (observing host, peer).** The protocol and the port are not in the key, so when there are
several edges to the same peer (for example TLS and SSH to the same node), one line fills all of them.

```bash
pqcota-declare-attribution --out ./declared-attr examples/inventory/attribution.csv
pqcota-ingest ./declared-attr
```

What the first line produces is **a `CollectionResult` in the declaration lane** (no `detection_method` = UNSPECIFIED).
`run.sh` prints that JSON as it is, so you can see what gets created.

> **It does not edit the observation.** The declaration accumulates in its own lane and the observed edge stays as it was. Combining the two
> happens **on the screen at query time**, and it fills only the blanks without overwriting an app the observation already caught. What was filled
> is shown as `@app(declared)`. There are two reasons to keep them apart in storage. The signature covers `app_key`, so
> editing it would differ from what the collector signed, and recomputing from the original would differ from the stored value.
>
> **The combined screen appears only in `pqcota-inventory` (Postgres).** The overlay that does the layering reads the declaration
> store, so this file-collation view (`pqcota-discover-view`), which has no store, does not reach that step. To see it end to end, use
> the central persistent query below or run [demo/](https://github.com/randyinthedev-hash/pqcota/tree/main/demo).

## Central persistent query (`pqcota-inventory`)
To query **an accumulated inventory that several nodes built up over time**, rather than a file collation, you need Postgres:
```bash
# first load into the same DSN (pqcota-ingest), then:
PQCOTA_DSN=postgres://… go run ./cmd/pqcota-inventory
```
→ up to the ▸ endpoint and profile header and the `@` app labels (a shared .so shows several). For the end-to-end flow see [demo/](https://github.com/randyinthedev-hash/pqcota/tree/main/demo). Command map: [cmd/README](../../cmd/README.md).

### `pqcota-cbom-ingest`: receive a CBOM produced by an external tool
For sources and build artifacts that a collector does not observe, it **receives** the standard CycloneDX produced by **CBOMkit** or similar in the user's CI, and loads it. Feeding it [`sample-cbom.json`](sample-cbom.json) gives:
```
✓ accepted: node=node-b · detection_method=source/artifact · 1 assets · store in-memory (summary only — gone when the process exits)
```
- **Validation (structure and anchors) is enforced inside the command**: a non-conforming CBOM is rejected (not stored). No separate preflight is needed. The signature gate is not wired, and the command says so on every run.
- It attaches through the observation lane (`detection_method=source/artifact`) and **converges into the same inventory as the collector observations** (when persisted in Postgres).

> **A note on the sample's shape**: normalization currently reads the CBOM's **`pqcota:` properties** ([`sample-cbom.json`](sample-cbom.json) has that shape, as if JCA/BouncyCastle had been found in source). Mapping the CBOMkit standard output (`cryptoProperties`) onto the pqcota schema is an **extension point** of the import adapter. For now only pqcota-mapped CBOMs are parsed into assets.
