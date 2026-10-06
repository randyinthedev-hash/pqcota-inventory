// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"math/rand"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// 참조용 지문 v1. 다운스트림이 같은 스냅샷을 같은 규칙으로 만들어 같은 값을 내고, 이력이 그
// 값으로 찾는다. 그래서 (1) 닫혀 있어야 하고 (2) 중복 억제 지문이 못 보던 것을 봐야 하며
// (3) 입력 순서에 흔들리지 않아야 한다.

func v1Fixture() *history.Snapshot {
	return &history.Snapshot{
		NodeID: "web-01", RulesetVersion: "pqcota-enrich/v2", ExcludedByScope: 2,
		Findings: []*discoveryv1.Finding{
			{Id: "f-b", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA, Algorithm: "RSA",
				RuntimeAxes: &discoveryv1.Finding_Jca{Jca: &discoveryv1.JcaAxes{JdkVendor: "temurin", JdkVersion: "21", ProviderSet: []string{"SUN", "BC"}}}},
			{Id: "f-a", CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL, Algorithm: "X25519",
				PqcReadiness: "not-ready", RemediationClass: "provider-inject", AppKeys: []string{"nginx", "haproxy"},
				RuntimeAxes: &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{Lib: "libcrypto.so.3", Version: "3.0.2"}}},
		},
		Edges: []*discoveryv1.ObservedEdge{
			{SrcNodeId: "web-01", DstNodeId: "pay-db", Port: 5432, NegotiatedGroup: "x25519", Cipher: "TLS_AES_128_GCM_SHA256", AppKey: "nginx", AppKeyKind: "systemd-unit"},
			{SrcNodeId: "web-01", DstNodeId: "pay-db", Port: 5432, NegotiatedGroup: "x25519", Cipher: "TLS_AES_256_GCM_SHA384", AppKey: "nginx", AppKeyKind: "systemd-unit"},
		},
		Completeness: &commonv1.Completeness{
			LayersCovered: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS, commonv1.CollectionLayer_COLLECTION_LAYER_NETWORK},
			LayersMissing: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_ARTIFACT},
			Note:          "artifact layer skipped",
		},
	}
}

// ★ v1은 닫혀 있다. 이 값이 바뀌면 이미 저장된 v1 참조가 같은 규칙으로 다시 계산되지 않는다.
// 바꿔야 하면 v2를 만든다 — 이 상수와 이 테스트를 고치는 것이 아니라.
const frozenV1 = "7818cb766fc54daeb8eaf602addd430e7830038d7421dcd8afee35e40b775e15"

func TestContentHashV1IsFrozen(t *testing.T) {
	got := history.ContentHashV1(v1Fixture())
	if frozenV1 == "" {
		t.Fatalf("frozenV1 을 채우라: %s", got)
	}
	if got != frozenV1 {
		t.Fatalf("v1 지문이 바뀌었다. v1 은 닫혀 있다 — 바꿔야 하면 v2 를 만든다.\n got  %s\n want %s", got, frozenV1)
	}
}

// v1이 중복 억제 지문(ContentHash)이 못 보던 것을 본다. 각각 v1만 달라지고 옛 지문은 그대로여야
// 두 용도가 실제로 갈린 것이다.
func TestContentHashV1CoversWhatDedupHashDoesNot(t *testing.T) {
	base := v1Fixture()
	for name, mut := range map[string]func(*history.Snapshot){
		"규칙 판":                 func(s *history.Snapshot) { s.RulesetVersion = "pqcota-enrich/v3" },
		"제외 수":                 func(s *history.Snapshot) { s.ExcludedByScope = 3 },
		"본 계층(layers_covered)": func(s *history.Snapshot) { s.Completeness.LayersCovered = s.Completeness.LayersCovered[:1] },
		"엣지의 앱":                func(s *history.Snapshot) { s.Edges[0].AppKey = "haproxy" },
		"엣지의 앱 출처":             func(s *history.Snapshot) { s.Edges[0].AppKeyKind = "exe-path" },
	} {
		other := v1Fixture()
		mut(other)
		if history.ContentHashV1(base) == history.ContentHashV1(other) {
			t.Errorf("%s가 바뀌었는데 v1 이 그대로다", name)
		}
		if history.ContentHash(base) != history.ContentHash(other) {
			t.Errorf("%s: 중복 억제 지문까지 달라졌다 — 두 용도가 갈리지 않았다", name)
		}
	}
}

// ★ 입력 순서에 흔들리지 않는다. finding·엣지·계층·앱 키의 순서를 섞어도 같다. 흔들리면
// 다운스트림이 같은 결과 집합으로 다른 값을 내 참조가 찾히지 않는다.
func TestContentHashV1IsOrderInvariant(t *testing.T) {
	want := history.ContentHashV1(v1Fixture())
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 20; i++ {
		s := v1Fixture()
		r.Shuffle(len(s.Findings), func(a, b int) { s.Findings[a], s.Findings[b] = s.Findings[b], s.Findings[a] })
		r.Shuffle(len(s.Edges), func(a, b int) { s.Edges[a], s.Edges[b] = s.Edges[b], s.Edges[a] })
		c := s.Completeness.LayersCovered
		r.Shuffle(len(c), func(a, b int) { c[a], c[b] = c[b], c[a] })
		// AppKeys는 finding의 값이라 그 순서도 흔들어 본다.
		for _, f := range s.Findings {
			r.Shuffle(len(f.AppKeys), func(a, b int) { f.AppKeys[a], f.AppKeys[b] = f.AppKeys[b], f.AppKeys[a] })
		}
		if got := history.ContentHashV1(s); got != want {
			t.Fatalf("순서를 섞었더니 v1 이 달라졌다 (%d번째)", i)
		}
	}
}

// 같은 키의 엣지가 여럿일 때 — 암호군만 다른 둘 — 순서를 바꿔도 같아야 한다. 옛 지문은 정렬
// 키에 암호군이 없어 여기서 흔들릴 수 있었다.
func TestContentHashV1SortsEdgesByFullIdentity(t *testing.T) {
	a := v1Fixture()
	b := v1Fixture()
	b.Edges[0], b.Edges[1] = b.Edges[1], b.Edges[0]
	if history.ContentHashV1(a) != history.ContentHashV1(b) {
		t.Fatal("암호군만 다른 두 엣지의 순서에 v1 이 흔들린다")
	}
	// 그리고 그 둘은 실제로 서로 다른 엣지다 — 하나를 지우면 값이 바뀐다.
	c := v1Fixture()
	c.Edges = c.Edges[:1]
	if history.ContentHashV1(a) == history.ContentHashV1(c) {
		t.Fatal("엣지 하나가 사라졌는데 v1 이 그대로다")
	}
}
