// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// JCA 식별 1단계(규칙 판 v4): 배포본 하나에 설정 변형 목록. finding id와 변경 감지 지문을 따로 잰다.

type variant struct {
	key      string // variantKey를 만들 씨앗(시험에서는 아무 문자열이나 해시한다)
	observed bool
	chain    []string
	services string
	modes    map[string]uint32
}

func vk(seed string) string {
	s := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(s[:])
}

func instancesJSON(t *testing.T, vs []variant) string {
	t.Helper()
	type mc struct {
		Mode  string `json:"mode"`
		Count uint32 `json:"count"`
	}
	type in struct {
		VariantKey         string         `json:"variantKey"`
		JavaHome           string         `json:"javaHome"`
		SecurityProperties map[string]any `json:"securityProperties"`
		ChainObserved      bool           `json:"chainObserved"`
		ProviderSet        []string       `json:"providerSet,omitempty"`
		PqcServices        string         `json:"pqcServices,omitempty"`
		ModeCounts         []mc           `json:"modeCounts"`
		Count              uint32         `json:"count"`
	}
	var out []in
	for _, v := range vs {
		var n uint32
		var mcs []mc
		for m, c := range v.modes {
			mcs = append(mcs, mc{m, c})
			n += c
		}
		out = append(out, in{VariantKey: vk(v.key), JavaHome: "/opt/jdk", SecurityProperties: map[string]any{"set": false, "value": ""},
			ChainObserved: v.observed, ProviderSet: v.chain, PqcServices: v.services, ModeCounts: mcs, Count: n})
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func jcaDeployment(t *testing.T, node, name, kind string, vs []variant) *discoveryv1.CollectionResult {
	t.Helper()
	props := []map[string]string{
		{"name": "pqcota:crypto_runtime", "value": "jca"},
		{"name": "pqcota:detection_method", "value": "runtime-introspection"},
	}
	if kind != "" {
		props = append(props, map[string]string{"name": "pqcota:jca.app_key_kind", "value": kind})
	}
	if vs != nil {
		props = append(props, map[string]string{"name": "pqcota:jca.instances", "value": instancesJSON(t, vs)})
	}
	doc := map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6",
		"components": []any{map[string]any{"type": "cryptographic-asset", "name": name, "properties": props}}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: node, CollectorId: "jvm-collector", CollectedAt: timestamppb.New(time.Unix(1800000000, 0))},
		CbomCyclonedx: b,
	}
}

func normalizeJCA(t *testing.T, rs ...*discoveryv1.CollectionResult) *history.Snapshot {
	t.Helper()
	snap, err := normalize.Normalize(rs, "snap", rs[0].GetEnvelope().GetTargetNodeId(), normalize.RulesetVersion, history.NewMemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

const bcServices = "BC=ML-KEM-768|ML-DSA-65|SLH-DSA-SHA2-128S,SUN=,SunRsaSign="

var (
	chainBC = []string{"SUN", "SunRsaSign", "BC"}
	chainNo = []string{"SUN", "SunRsaSign"}
)

// JVM 수(count)나 관측 방식별 수(mode_counts)만 바뀌면 **finding id는 그대로이고 지문은 달라지며, diff는
// changed로 보인다.**
func TestJCAVariantCountsChangeTheFingerprintNotTheID(t *testing.T) {
	name := "jca-provider-chain@/opt/a/app.jar"
	base := normalizeJCA(t, jcaDeployment(t, "pay", name, "jar-path", []variant{
		{key: "v1", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 3}}}))
	for label, vs := range map[string][]variant{
		"JVM 수만 바뀜": {{key: "v1", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 2}}},
		"관측 방식만 바뀜": {{key: "v1", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 2, "static": 1}}},
	} {
		other := normalizeJCA(t, jcaDeployment(t, "pay", name, "jar-path", vs))
		if base.Findings[0].GetId() != other.Findings[0].GetId() {
			t.Errorf("%s: finding id changed", label)
		}
		if history.ContentHashV1(base) == history.ContentHashV1(other) || history.ContentHash(base) == history.ContentHash(other) {
			t.Errorf("%s: the fingerprint did not change", label)
		}
		base.CreatedAt, other.CreatedAt = time.Unix(1, 0), time.Unix(2, 0)
		diff := inventory.RenderDiff(base, other)
		if !strings.Contains(diff, "changed") || !strings.Contains(diff, "~ "+base.Findings[0].GetId()[:12]) {
			t.Errorf("%s: the diff does not show the deployment as changed:\n%s", label, diff)
		}
	}
}

// 같은 관측을 다른 순서로 넣으면(변형의 순서, 모드의 순서, 결과의 순서) **id와 지문이 모두 같다.**
func TestJCASameObservationInAnotherOrder(t *testing.T) {
	vs := []variant{
		{key: "v1", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 2, "static": 1}},
		{key: "v2", observed: true, chain: chainNo, services: "SUN=,SunRsaSign=", modes: map[string]uint32{"dynamic": 1}},
		{key: "v3", observed: false, modes: map[string]uint32{"": 1}},
	}
	rev := []variant{vs[2], vs[1], vs[0]}
	other := jcaDeployment(t, "pay", "jca-provider-chain@/opt/b/app.jar", "jar-path", []variant{{key: "w", observed: true, chain: chainNo, modes: map[string]uint32{"dynamic": 1}}})
	a := normalizeJCA(t, jcaDeployment(t, "pay", "jca-provider-chain@/opt/a/app.jar", "jar-path", vs), other)
	for i := 0; i < 20; i++ { // map 순회가 모드 순서를 섞는다
		b := normalizeJCA(t, other, jcaDeployment(t, "pay", "jca-provider-chain@/opt/a/app.jar", "jar-path", rev))
		if history.ContentHashV1(a) != history.ContentHashV1(b) || history.ContentHash(a) != history.ContentHash(b) {
			t.Fatalf("the fingerprint depends on the input order")
		}
		ida, idb := map[string]bool{}, map[string]bool{}
		for _, f := range a.Findings {
			ida[f.GetId()] = true
		}
		for _, f := range b.Findings {
			idb[f.GetId()] = true
		}
		if len(ida) != 2 || len(idb) != 2 {
			t.Fatalf("finding count: %d %d", len(ida), len(idb))
		}
		for id := range ida {
			if !idb[id] {
				t.Fatalf("the ids depend on the input order")
			}
		}
	}
}

// 새 형식은 필드 경계를 보존한다. 옛 `|` 이음에서 같은 바이트가 되는 짝이 새 형식에서는 id 둘이다.
func TestJCANewIDKeepsFieldBoundaries(t *testing.T) {
	legacy := func(node, name string) string { // findingID의 옛 이음과 같은 꼴
		s := sha256.Sum256([]byte(strings.Join([]string{node, name, "jca", ""}, "|")))
		return hex.EncodeToString(s[:])
	}
	if legacy("n|x", "jca-provider-chain@y") != legacy("n", "x|jca-provider-chain@y") {
		t.Fatal("the pair does not collide under the old join — the test is not measuring anything")
	}
	vs := []variant{{key: "v", observed: true, chain: chainBC, modes: map[string]uint32{"dynamic": 1}}}
	a := normalizeJCA(t, jcaDeployment(t, "n|x", "jca-provider-chain@y", "jar-path", vs))
	b := normalizeJCA(t, jcaDeployment(t, "n", "x|jca-provider-chain@y", "jar-path", vs))
	if a.Findings[0].GetId() == b.Findings[0].GetId() {
		t.Error("two inputs whose fields differ got one id")
	}
	// 키 값 안의 `|`도 같다.
	c := normalizeJCA(t, jcaDeployment(t, "n", "jca-provider-chain@/opt/a|b/app.jar", "jar-path", vs))
	d := normalizeJCA(t, jcaDeployment(t, "n", "jca-provider-chain@/opt/a", "jar-path|b/app.jar", vs))
	if c.Findings[0].GetId() == d.Findings[0].GetId() {
		t.Error("a | inside the key moved a field boundary")
	}
}

// 키 값이 같아도 종류가 다르면 다른 배포본이다: `-jar foo.service`의 약한 키와 systemd의 foo.service.
func TestJCAKindIsPartOfTheID(t *testing.T) {
	vs := []variant{{key: "v", observed: true, chain: chainBC, modes: map[string]uint32{"dynamic": 1}}}
	jar := normalizeJCA(t, jcaDeployment(t, "n", "jca-provider-chain@foo.service", "jar-name", vs))
	unit := normalizeJCA(t, jcaDeployment(t, "n", "jca-provider-chain@foo.service", "systemd-unit", vs))
	if jar.Findings[0].GetId() == unit.Findings[0].GetId() {
		t.Error("jar-name foo.service and systemd-unit foo.service got one id")
	}
	if jar.Findings[0].GetJca().GetAppKeyKind() != "jar-name" {
		t.Errorf("app_key_kind = %q", jar.Findings[0].GetJca().GetAppKeyKind())
	}
}

// finding 한 장의 값: 같으면 그 값, 다르면 「varies」, 체인이 섞이거나 일부를 못 봤으면 빈 체인.
func TestJCAFindingValues(t *testing.T) {
	bcReady := func() string {
		f := normalizeJCA(t, jcaDeployment(t, "n", "c", "jar-path", []variant{{key: "x", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 1}}})).Findings[0]
		return f.GetPqcReadiness()
	}()
	cases := []struct {
		name      string
		vs        []variant
		chain     []string
		readiness string
		mode      commonv1.JcaRegistrationMode
	}{
		{"레플리카 셋, 같은 체인", []variant{{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 3}}},
			chainBC, bcReady, commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_DYNAMIC},
		{"체인 둘, readiness 다름", []variant{
			{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 1}},
			{key: "b", observed: true, chain: chainNo, services: "SUN=,SunRsaSign=", modes: map[string]uint32{"dynamic": 1}}},
			nil, "varies (2 variants)", commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_DYNAMIC},
		{"체인 둘, readiness 같음", []variant{
			{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 1}},
			{key: "b", observed: true, chain: []string{"BC", "SUN", "SunRsaSign"}, services: bcServices, modes: map[string]uint32{"dynamic": 1}}},
			nil, bcReady, commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_DYNAMIC},
		{"셋은 같은 체인, 넷째는 못 봄", []variant{
			{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 3}},
			{key: "b", observed: false, modes: map[string]uint32{"": 1}}},
			nil, "varies (2 variants)", commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_UNSPECIFIED},
		{"정적 폴백과 attach가 같은 체인", []variant{{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"dynamic": 1, "static": 1}}},
			chainBC, bcReady, commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_UNSPECIFIED},
		{"정적 폴백 하나", []variant{{key: "a", observed: true, chain: chainBC, services: bcServices, modes: map[string]uint32{"static": 1}}},
			chainBC, bcReady, commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_STATIC},
	}
	for _, c := range cases {
		f := normalizeJCA(t, jcaDeployment(t, "n", "jca-provider-chain@/opt/a/app.jar", "jar-path", c.vs)).Findings[0]
		j := f.GetJca()
		if strings.Join(j.GetProviderSet(), ",") != strings.Join(c.chain, ",") || f.GetPqcReadiness() != c.readiness || j.GetRegistrationMode() != c.mode {
			t.Errorf("%s: provider_set %v readiness %q mode %v; want %v %q %v", c.name, j.GetProviderSet(), f.GetPqcReadiness(), j.GetRegistrationMode(), c.chain, c.readiness, c.mode)
		}
		if len(j.GetInstances()) != len(c.vs) {
			t.Errorf("%s: %d instances, want %d", c.name, len(j.GetInstances()), len(c.vs))
		}
		for _, in := range j.GetInstances() {
			if !in.GetChainObserved() && (in.GetPqcReadiness() != "unknown" || len(in.GetProviderSet()) != 0) {
				t.Errorf("%s: an unobserved variant has readiness %q and chain %v", c.name, in.GetPqcReadiness(), in.GetProviderSet())
			}
		}
	}
}

// 변형 정보가 깨졌으면 받지 않는다(서명된 수집기 출력이 깨졌다는 뜻이다).
func TestJCAMalformedInstancesAreRefused(t *testing.T) {
	for name, raw := range map[string]string{
		"빈 목록":         `[]`,
		"짧은 키":         `[{"variantKey":"abc","chainObserved":true,"modeCounts":[{"mode":"dynamic","count":1}],"count":1}]`,
		"수가 맞지 않음":     `[{"variantKey":"` + vk("a") + `","chainObserved":true,"modeCounts":[{"mode":"dynamic","count":1}],"count":2}]`,
		"못 봤는데 체인이 있음": `[{"variantKey":"` + vk("a") + `","chainObserved":false,"providerSet":["SUN"],"modeCounts":[{"mode":"","count":1}],"count":1}]`,
		"같은 키 둘":       `[{"variantKey":"` + vk("a") + `","chainObserved":true,"modeCounts":[{"mode":"dynamic","count":1}],"count":1},{"variantKey":"` + vk("a") + `","chainObserved":true,"modeCounts":[{"mode":"dynamic","count":1}],"count":1}]`,
		"모르는 모드":       `[{"variantKey":"` + vk("a") + `","chainObserved":true,"modeCounts":[{"mode":"weird","count":1}],"count":1}]`,
	} {
		doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"cryptographic-asset","name":"c","properties":[
			{"name":"pqcota:crypto_runtime","value":"jca"},{"name":"pqcota:jca.app_key_kind","value":"jar-path"},
			{"name":"pqcota:jca.instances","value":` + strings.ReplaceAll(jsonString(raw), "\n", "") + `}]}]}`
		res := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{TargetNodeId: "n"}, CbomCyclonedx: []byte(doc)}
		if _, err := normalize.DeriveFindings(res, "s", "r"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
