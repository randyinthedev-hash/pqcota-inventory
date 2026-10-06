// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package normalize_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// openssl-collector가 낼 법한 CollectionResult(CycloneDX + Envelope + 완전성) 픽스처.
func opensslResult(node string) *discoveryv1.CollectionResult {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"libcrypto","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection+symbol-analysis"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.binding_mode","value":"dynamic"}]}]}`)
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{
			TargetNodeId:    node,
			DetectionMethod: commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION,
		},
		CbomCyclonedx:        cbom,
		CyclonedxSpecVersion: "1.6",
		Completeness: &commonv1.Completeness{
			LayersCovered: []commonv1.CollectionLayer{commonv1.CollectionLayer_COLLECTION_LAYER_PROCESS},
		},
	}
}

func TestDeriveFindings(t *testing.T) {
	fs, err := normalize.DeriveFindings(opensslResult("cmdb://n1"), "snap-1", "ruleset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.GetCryptoRuntime() != commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL {
		t.Errorf("crypto_runtime = %v, want OPENSSL", f.GetCryptoRuntime())
	}
	if f.GetEvidenceStrength() != commonv1.EvidenceStrength_EVIDENCE_STRENGTH_CONFIRMED {
		t.Errorf("evidence_strength = %v, want CONFIRMED (runtime-introspection)", f.GetEvidenceStrength())
	}
	if f.GetOpenssl().GetFork() != "OpenSSL" {
		t.Errorf("fork = %q", f.GetOpenssl().GetFork())
	}
	if f.GetOpenssl().GetBindingMode() != commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_DYNAMIC {
		t.Errorf("binding_mode = %v, want DYNAMIC", f.GetOpenssl().GetBindingMode())
	}
	if f.GetDerivedFromSnapshotId() != "snap-1" || f.GetRulesetVersion() != "ruleset-1" {
		t.Errorf("the derivation-tracking fields are missing: %+v", f)
	}
	if f.GetId() == "" {
		t.Error("the finding id (normalization hash) is empty")
	}
}

// #3 한 자산에 앱 여럿: pqcota:app_keys CSV → Finding.app_keys(정렬·복수).
func TestDeriveFindings_MultiApp(t *testing.T) {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"libcrypto","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:app_keys","value":"api.service,payment.service"}]}]}`)
	res := &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: "cmdb://n1"},
		CbomCyclonedx: cbom,
	}
	fs, err := normalize.DeriveFindings(res, "s", "r")
	if err != nil {
		t.Fatal(err)
	}
	if got := fs[0].GetAppKeys(); len(got) != 2 || got[0] != "api.service" || got[1] != "payment.service" {
		t.Errorf("failed to parse the several apps on a shared .so: %v", got)
	}
}

func jcaResult(node, providerSet string) *discoveryv1.CollectionResult {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"jca-provider-chain","properties":[
        {"name":"pqcota:crypto_runtime","value":"jca"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:jca.provider_set","value":"` + providerSet + `"}]}]}`)
	return &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: node},
		CbomCyclonedx: cbom,
	}
}

func TestDeriveFindings_JCA(t *testing.T) {
	// BC 포함 → 전 표준 알고리즘 커버, SLH-DSA 갭 없음.
	fs, _ := normalize.DeriveFindings(jcaResult("cmdb://j1", "SUN,BC"), "s", "r")
	f := fs[0]
	if f.GetCryptoRuntime() != commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA {
		t.Fatalf("crypto_runtime = %v, want JCA", f.GetCryptoRuntime())
	}
	if len(f.GetJca().GetProviderSet()) != 2 {
		t.Errorf("provider_set = %v", f.GetJca().GetProviderSet())
	}
	if f.GetPqcReadiness() != "provider-augmented (all standard algorithms)" {
		t.Errorf("pqc_readiness = %q (BC does cover SLH-DSA)", f.GetPqcReadiness())
	}

	// JDK 네이티브만(SunJCE) → SLH-DSA 갭.
	fs2, _ := normalize.DeriveFindings(jcaResult("cmdb://j2", "SUN,SunJCE"), "s", "r")
	if got := fs2[0].GetPqcReadiness(); got != "provider-augmented (SLH-DSA gap)" {
		t.Errorf("pqc_readiness = %q, want the SLH-DSA gap", got)
	}
}

func TestNormalizePipeline(t *testing.T) {
	store := history.NewMemStore()

	// dedup: 동일 노드·컴포넌트를 두 번 넣어도 하나로 수렴(§2.4⑤).
	results := []*discoveryv1.CollectionResult{opensslResult("cmdb://n1"), opensslResult("cmdb://n1")}
	snap, err := normalize.Normalize(results, "snap-1", "cmdb://n1", "ruleset-1", store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Findings) != 1 {
		t.Fatalf("dedup failed: %d findings, want 1", len(snap.Findings))
	}
	// 히스토리 append 확인.
	if latest, _ := store.Latest("cmdb://n1"); latest == nil || latest.ID != "snap-1" {
		t.Error("no snapshot was appended to the history")
	}

	// 재현성: 같은 입력+ruleset → 같은 finding id(§1.2).
	snap2, _ := normalize.Normalize([]*discoveryv1.CollectionResult{opensslResult("cmdb://n1")}, "snap-2", "cmdb://n1", "ruleset-1", store, nil)
	if snap.Findings[0].GetId() != snap2.Findings[0].GetId() {
		t.Error("determinism broken: the same input produced different finding ids")
	}
	// 같은 내용을 다시 관측한 것이라 스냅샷은 늘지 않고(중복 억제) 관측 기록만 쌓인다.
	if snaps, _ := store.Snapshots("cmdb://n1"); len(snaps) != 1 {
		t.Errorf("re-observing identical content → %d snapshots, want 1", len(snaps))
	}
	if stats, _ := store.ObservationStats("cmdb://n1"); stats["snap-1"].Count != 2 {
		t.Errorf("observation count = %d, want 2 (the fact that we looked is kept)", stats["snap-1"].Count)
	}
}

// TK-PIPELINE-CNG — 실측 그대로의 CNG 관측이 파생 뷰까지 간다.
//
// 아래 값은 지어낸 것이 아니라 **Windows 11 Pro 25H2(빌드 26200)에서 관측한 것**이다. provider
// 이름 9개는 전부 Microsoft라 그것만으로는 이 노드의 PQC 가능 여부를 답할 수 없다 — 답은
// 알고리즘 목록에 있고(ML-DSA 있음·ML-KEM 없음), 그래서 계약에 알고리즘 축을 더했다.
func TestDeriveFindings_CNG(t *testing.T) {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"cng-providers","properties":[
        {"name":"pqcota:crypto_runtime","value":"cng"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:cng.provider_set","value":"Microsoft Key Protection Provider,Microsoft Primitive Provider,Microsoft SSL Protocol Provider"},
        {"name":"pqcota:cng.algorithms","value":"AES:cipher,ECDH_P256:secret-agreement,ML-DSA:signature,RSA:asymmetric-encryption,SHA256:hash"}]}]}`)
	res := &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: "cmdb://win-01"},
		CbomCyclonedx: cbom,
	}
	fs, err := normalize.DeriveFindings(res, "snap-1", "ruleset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.GetCryptoRuntime() != commonv1.CryptoRuntime_CRYPTO_RUNTIME_WIN_CNG {
		t.Errorf("crypto_runtime = %v, want WIN_CNG", f.GetCryptoRuntime())
	}
	// provider 순서는 관측된 등록 순서다 — 파생에서 흔들리면 안 된다.
	if got := f.GetCng().GetProviderSet(); len(got) != 3 || got[0] != "Microsoft Key Protection Provider" {
		t.Errorf("provider_set did not arrive in order: %v", got)
	}
	algs := f.GetCng().GetAlgorithms()
	if len(algs) != 5 {
		t.Fatalf("%d algorithms, want 5", len(algs))
	}
	var mldsa, ecdh string
	for _, a := range algs {
		switch a.GetName() {
		case "ML-DSA":
			mldsa = a.GetClass()
		case "ECDH_P256":
			ecdh = a.GetClass()
		}
	}
	// 이 두 줄이 이 릴리스의 질문에 답한다: 서명은 양자내성으로 갈 수 있고, 키 교환은 못 간다.
	if mldsa != "signature" {
		t.Errorf("ML-DSA did not reach the derived view (class=%q) — living only in the raw capture means it is never queried", mldsa)
	}
	if ecdh != "secret-agreement" {
		t.Errorf("ECDH_P256 has class %q — the measurement says secret-agreement", ecdh)
	}
	for _, a := range algs {
		if a.GetName() == "ML-KEM" {
			t.Error("an ML-KEM that was never observed appeared in the derived view — something absent was invented")
		}
	}
	// readiness는 판정이 아니라 관측의 요약이다. 서명만 있고 KEM은 없는 것이 이 노드의 사실이다.
	if got := f.GetPqcReadiness(); got != "native (signature only — no KEM observed)" {
		t.Errorf("pqc_readiness = %q — the measurement is ML-DSA present, ML-KEM absent", got)
	}
	// CNG의 FIPS 모드는 알고리즘 열거로 알 수 없다 — 모른다고 적어야 한다(§2.5).
	if got := f.GetFipsValidation(); got != "unknown" {
		t.Errorf("fips_validation = %q — asserting something that was never observed", got)
	}
}

// 알고리즘을 하나도 못 본 CNG 결과는 "고전뿐"이 아니라 **모른다**여야 한다(§2.6 갭 ≠ 부재).
func TestDeriveFindings_CNG_NoAlgorithmsIsUnknown(t *testing.T) {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"cng-providers","properties":[
        {"name":"pqcota:crypto_runtime","value":"cng"},
        {"name":"pqcota:cng.provider_set","value":"Microsoft Primitive Provider"}]}]}`)
	fs, err := normalize.DeriveFindings(&discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: "cmdb://win-01"},
		CbomCyclonedx: cbom,
	}, "snap-1", "ruleset-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := fs[0].GetPqcReadiness(); got != "unknown" {
		t.Errorf("no algorithm was observed, yet readiness = %q — recording the unseen as absent", got)
	}
}
