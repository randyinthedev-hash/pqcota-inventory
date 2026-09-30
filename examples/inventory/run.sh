#!/usr/bin/env bash
# examples/inventory — 회수된 CollectionResult를 읽기전용 인벤토리 뷰로 조회한다(자산·앱 표시·등급).
# 전제: Go 툴체인만. 저장소·타깃 노드 불필요(파일 취합 모드).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$ROOT"

echo "▶ pqcota-discover-view — collate ../data/results → discovered assets + observed edge grades + topology DOT"
echo "   (nodes.json resolves observed IPs to node names: 10.0.0.9 → node-c)"
echo
go run ./inventory/cmd/pqcota-discover-view \
    "$ROOT/examples/data/results" \
    "$ROOT/examples/data/nodes.json" \
    "$TMP/topology.dot"

echo
echo "head of the generated topology DOT (colour = grade):"
head -6 "$TMP/topology.dot" | sed 's/^/   /'
echo
echo "▶ pqcota-declare-attribution — a person names the app for an edge the capture missed"
echo "   (a short-lived connection is gone by lookup time, so app_key stays empty — see attribution.csv)"
go run ./inventory/cmd/pqcota-declare-attribution --out "$TMP/declared-attr" "$HERE/attribution.csv"
echo
echo "the declared-lane result (the observed edges themselves are untouched):"
sed 's/^/   /' "$TMP/declared-attr/attribution-000.json"
echo

echo
echo "▶ pqcota-cbom-ingest — validate and ingest a CBOM produced by an external tool"
echo "   (source and build artifacts, which no collector observes, arrive as standard CycloneDX from your CI)"
go run ./inventory/cmd/pqcota-cbom-ingest "$HERE/sample-cbom.json" node-b

echo
echo "✅ ran the file-collation view (ephemeral), the declared-lane import, and the external CBOM intake."
echo "   • central persistent query (with endpoint and profile headers): PQCOTA_DSN=<postgres> go run ./inventory/cmd/pqcota-inventory"
echo "     (ingest into the same DSN with pqcota-ingest first — see demo/)"
