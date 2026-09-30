package inventory_test

import (
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// -diff 방향 규약: 첫 인자=과거, 둘째=최신. 추가=둘째에만, 사라짐=첫째에만. 인자를 시간 역순으로
// 주면 방향이 뒤집혀 읽히므로 경고가 떠야 한다(리뷰 지적 — 사용자 오독 예방).
func TestRenderDiffDirection(t *testing.T) {
	mk := func(id, lib string) *discoveryv1.Finding {
		return &discoveryv1.Finding{
			Id: id, CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
			RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: lib, Version: "3.0"}},
		}
	}
	older := &history.Snapshot{ID: "old", NodeID: "n1", Seq: 1, RulesetVersion: "r1",
		CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings:  []*discoveryv1.Finding{mk("A", "libssl.so.3")}}
	newer := &history.Snapshot{ID: "new", NodeID: "n1", Seq: 2, RulesetVersion: "r1",
		CreatedAt: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Findings:  []*discoveryv1.Finding{mk("A", "libssl.so.3"), mk("B", "libcrypto.so.3")}}

	// 시간순(과거,최신): 새 자산 B는 '추가'. 역순 경고 없음.
	fwd := inventory.RenderDiff(older, newer)
	if !strings.Contains(fwd, "added") || !strings.Contains(fwd, "libcrypto.so.3") {
		t.Errorf("old→latest: a new asset must read as 'added':\n%s", fwd)
	}
	if strings.Contains(fwd, "reverse order") {
		t.Errorf("the order is forward yet a reversed-order warning appeared:\n%s", fwd)
	}

	// 역순(최신,과거): 같은 B가 '사라짐'으로 뒤집히고 역순 경고가 떠야 한다.
	rev := inventory.RenderDiff(newer, older)
	if !strings.Contains(rev, "removed") {
		t.Errorf("latest→old: the same asset must flip to 'removed':\n%s", rev)
	}
	if !strings.Contains(rev, "reverse order") {
		t.Errorf("arguments in reverse time order must be warned about:\n%s", rev)
	}
}

// TV-INGEST-4 — e2e: collector 산출물(CycloneDX) → Normalize → 읽기전용 인벤토리 뷰.
func TestRenderEndToEnd(t *testing.T) {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"libcrypto","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection+symbol-analysis"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.version","value":"3.0.20"}]}]}`)
	res := &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: "cmdb://n1"},
		CbomCyclonedx: cbom,
		Completeness: &commonv1.Completeness{
			LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
			Note:          "network layer not collected",
		},
	}
	snap, err := normalize.Normalize([]*discoveryv1.CollectionResult{res}, "snap-1", "cmdb://n1", "r1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := inventory.Render(snap)
	for _, want := range []string{"cmdb://n1", "openssl", "confirmed", "libcrypto/OpenSSL 3.0.20", "gap"} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendered output does not contain %q:\n%s", want, out)
		}
	}
}

// TV-HISTORY-6 — ruleset이 다르면 파생값 차이가 실제 변화가 아닐 수 있다(§1.2). 구현은 오래
// 있었지만 테스트가 양쪽 ruleset을 같게 두어 이 줄을 한 번도 타지 않았다.
func TestRenderDiffWarnsOnRulesetChange(t *testing.T) {
	mk := func(ruleset string, seq int64, day int) *history.Snapshot {
		return &history.Snapshot{
			ID: "s" + ruleset, NodeID: "n1", Seq: seq, RulesetVersion: ruleset,
			CreatedAt: time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC),
			Findings: []*discoveryv1.Finding{{
				Id: "A", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL,
				RuntimeAxes: &discoveryv1.Finding_Openssl{
					Openssl: &discoveryv1.OpensslAxes{Lib: "libssl.so.3", Version: "3.0"}},
			}},
		}
	}
	const warn = "the rulesets differ"
	if out := inventory.RenderDiff(mk("r1", 1, 1), mk("r2", 2, 2)); !strings.Contains(out, warn) {
		t.Errorf("the ruleset changed but there is no recompute warning:\n%s", out)
	}
	// 같은 ruleset이면 뜨면 안 된다 — 매번 뜨는 경고는 읽히지 않는다.
	if out := inventory.RenderDiff(mk("r1", 1, 1), mk("r1", 2, 2)); strings.Contains(out, warn) {
		t.Errorf("the ruleset is the same yet a warning appeared:\n%s", out)
	}
}
