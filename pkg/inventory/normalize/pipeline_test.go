// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
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
	return jcaResultServices(node, providerSet, "")
}

// jcaResultServices — pqc_services(`provider=알고리즘|알고리즘` CSV)까지 실은 JCA 결과. 비면 그 속성을
// 싣지 않는다 — 수집기가 서비스를 보지 않은 경우다.
func jcaResultServices(node, providerSet, services string) *discoveryv1.CollectionResult {
	sprop := ""
	if services != "" {
		sprop = `,
        {"name":"pqcota:jca.pqc_services","value":"` + services + `"}`
	}
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"jca-provider-chain","properties":[
        {"name":"pqcota:crypto_runtime","value":"jca"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:jca.provider_set","value":"` + providerSet + `"}` + sprop + `]}]}`)
	return &discoveryv1.CollectionResult{
		Envelope:      &commonv1.Envelope{TargetNodeId: node},
		CbomCyclonedx: cbom,
	}
}

func TestDeriveFindings_JCA(t *testing.T) {
	// BC 포함, 서비스 미관측 → 레지스트리대로 전 표준 알고리즘. 판을 가리지 않는 기존 동작이다.
	fs, _ := normalize.DeriveFindings(jcaResult("cmdb://j1", "SUN,BC"), "s", "r")
	f := fs[0]
	if f.GetCryptoRuntime() != commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA {
		t.Fatalf("crypto_runtime = %v, want JCA", f.GetCryptoRuntime())
	}
	if len(f.GetJca().GetProviderSet()) != 2 {
		t.Errorf("provider_set = %v", f.GetJca().GetProviderSet())
	}
	if f.GetPqcReadiness() != "provider-augmented (all standard algorithms)" {
		t.Errorf("pqc_readiness = %q (the registry lists SLH-DSA for BC)", f.GetPqcReadiness())
	}

	// JDK 네이티브만, 서비스 미관측 → 세지 않는다. 이름으로는 21.0.12(없음)와 21.0.13(있음)을 가를 수 없다.
	fs2, _ := normalize.DeriveFindings(jcaResult("cmdb://j2", "SUN,SunJCE"), "s", "r")
	if got := fs2[0].GetPqcReadiness(); got != "unknown" {
		t.Errorf("pqc_readiness = %q, want unknown (JDK-native support is not credited from names)", got)
	}
}

// 2026-10-30 실측 체인(Temurin 21.0.11·21.0.13·25.0.5, 프로브). 판은 모두 기능 판("21"·"25")이고, 서비스 목록만 다르다.
const (
	jdkChain    = "SUN,SunRsaSign,SunEC,SunJSSE,SunJCE,SunJGSS,SunSASL,XMLDSig,SunPCSC,JdkLDAP,JdkSASL,SunPKCS11"
	jdkNoPQC    = "SUN=,SunRsaSign=,SunEC=,SunJSSE=,SunJCE=,SunJGSS=,SunSASL=,XMLDSig=,SunPCSC=,JdkLDAP=,JdkSASL=,SunPKCS11="
	jdkSUN      = "SUN=ML-DSA|ML-DSA-44|ML-DSA-65|ML-DSA-87"
	jdkSunJCE   = "SunJCE=ML-KEM|ML-KEM-1024|ML-KEM-512|ML-KEM-768"
	jdkWithPQC  = jdkSUN + ",SunRsaSign=,SunEC=,SunJSSE=," + jdkSunJCE + ",SunJGSS=,SunSASL=,XMLDSig=,SunPCSC=,JdkLDAP=,JdkSASL=,SunPKCS11="
	bcWithAll   = "BC=ML-DSA|ML-KEM|SLH-DSA-SHA2-128F"
	bcPreStdPQC = "BC=KYBER512|DILITHIUM2|SPHINCSPLUS"
)

// JCA readiness는 provider가 등록한 PQC 서비스를 센다. 2026-10-30 시연(pay-app, Temurin 21.0.11, BC 없음)의
// diff에 `provider-augmented (SLH-DSA gap)`이 나왔지만 그 JVM에는 ML-KEM 서비스가 등록돼 있지 않았다. 실측
// (Temurin)에서 21.0.11·21.0.12에는 없고 21.0.13(백포트)·24.0.2·25.0.5에는 SunJCE의 ML-KEM과 SUN의 ML-DSA가
// 있었다. SunEC는 어느 판에서도 둘 다 등록하지 않았다.
func TestDeriveFindings_JCAObservedServices(t *testing.T) {
	cases := []struct {
		name, set, services, want string
	}{
		{"Temurin 21.0.11 (demo pay-app), no BC", jdkChain, jdkNoPQC, "none (no standard PQC service observed)"},
		{"Temurin 21.0.13 backport, no BC", jdkChain, jdkWithPQC, "provider-augmented (SLH-DSA gap)"},
		{"Temurin 25.0.5, no BC", jdkChain, jdkWithPQC, "provider-augmented (SLH-DSA gap)"},
		// provider 하나씩: 체인 전체로는 같아 보여도 누가 무엇을 서비스하는지가 맞아야 한다.
		{"SunEC only", "SunEC", "SunEC=", "none (no standard PQC service observed)"},
		{"SUN only", "SUN", jdkSUN, "partial (only ML-DSA observed)"},
		{"SunJCE only", "SunJCE", jdkSunJCE, "partial (only ML-KEM observed)"},
		// 서비스가 있는데 체인에 없는 provider의 것은 세지 않는다.
		{"services of a provider outside the chain", "SunEC", "SunEC=," + jdkSunJCE, "none (no standard PQC service observed)"},
		// 일부만 관측한 체인. 속성에 키가 없는 provider는 「봤는데 없다」가 아니라 「보지 않았다」다.
		{"every provider observed, all empty", "SUN,SunJCE", "SUN=,SunJCE=", "none (no standard PQC service observed)"},
		{"SUN observed empty, SunJCE not observed", "SUN,SunJCE", "SUN=", "unknown"},
		{"SUN observed with ML-DSA, SunJCE not observed", "SUN,SunJCE", jdkSUN, "partial (only ML-DSA observed)"},
		// 관측하지 않은 BC는 레지스트리의 이름 대조로 센다(기존 동작). 서비스 목록을 본 것이 아니다.
		{"JDK observed empty, BC not observed (registry by name)", jdkChain + ",BC", jdkNoPQC, "provider-augmented (all standard algorithms)"},
		{"Temurin 21.0.11 + BC serving all three", jdkChain + ",BC", jdkNoPQC + "," + bcWithAll, "provider-augmented (all standard algorithms)"},
		// 표준 이전 이름(Kyber 등)은 표준 PQC 서비스로 세지 않는다.
		{"BC with pre-standard names only", jdkChain + ",BC", jdkNoPQC + "," + bcPreStdPQC, "none (no standard PQC service observed)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, err := normalize.DeriveFindings(jcaResultServices("cmdb://pay", c.set, c.services), "s", "r")
			if err != nil {
				t.Fatal(err)
			}
			if got := fs[0].GetPqcReadiness(); got != c.want {
				t.Errorf("pqc_readiness = %q, want %q", got, c.want)
			}
		})
	}
}

// 서비스를 보지 않은 입력(정적 폴백, 옛 수집기)은 JDK 기본 제공 provider를 세지 않는다. BC 등은 판을 가리지
// 않고 레지스트리대로 센다 — 기존 동작을 유지한 것이지 그 판의 서비스 목록을 확인한 것이 아니다.
func TestDeriveFindings_JCAServicesNotObserved(t *testing.T) {
	cases := []struct {
		name, set, want string
	}{
		{"JDK chain only", jdkChain, "unknown"},
		{"JDK chain + BC (existing registry behaviour, no version condition)", jdkChain + ",BC", "provider-augmented (all standard algorithms)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs, _ := normalize.DeriveFindings(jcaResult("cmdb://pay", c.set), "s", "r")
			if got := fs[0].GetPqcReadiness(); got != c.want {
				t.Errorf("pqc_readiness = %q, want %q", got, c.want)
			}
		})
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
