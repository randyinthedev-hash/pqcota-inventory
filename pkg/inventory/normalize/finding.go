// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/registry"
)

// cyclonedxDoc — 파싱에 필요한 최소 CycloneDX 형태(pqcota properties 포함).
type cyclonedxDoc struct {
	Components []struct {
		Name       string `json:"name"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
	} `json:"components"`
}

// DeriveFindings — 정규화 파이프라인 강화 단계(§2.4③). CollectionResult의 표준 CycloneDX +
// Envelope를 타입드 Finding으로 파생한다. evidence_strength는 detection_method에서 결정론적으로
// 부착되고(§2.5), 파생 뷰이므로 원본 재현을 위해 snapshotID·rulesetVersion을 기록한다(§1.2).
//
// ★ 이 강화는 코어 단독 책임 — Collector는 강화하지 않는다(설계 §3, contracts/README).
func DeriveFindings(res *discoveryv1.CollectionResult, snapshotID, rulesetVersion string) ([]*discoveryv1.Finding, error) {
	if len(res.GetCbomCyclonedx()) == 0 {
		return nil, nil
	}
	var doc cyclonedxDoc
	if err := json.Unmarshal(res.GetCbomCyclonedx(), &doc); err != nil {
		return nil, err
	}
	node := res.GetEnvelope().GetTargetNodeId()
	var out []*discoveryv1.Finding
	for _, c := range doc.Components {
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}

		dm := parseDetectionMethod(props["pqcota:detection_method"], res.GetEnvelope().GetDetectionMethod())
		runtime := parseCryptoRuntime(props["pqcota:crypto_runtime"])

		f := &discoveryv1.Finding{
			CryptoRuntime:         runtime,
			DetectionMethod:       dm,
			EvidenceStrength:      EvidenceStrength(dm), // 결정론적 파생
			DerivedFromSnapshotId: snapshotID,
			RulesetVersion:        rulesetVersion,
		}

		switch runtime {
		case commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL:
			f.RuntimeAxes = &discoveryv1.Finding_Openssl{Openssl: &discoveryv1.OpensslAxes{
				Lib:         c.Name,
				Fork:        props["pqcota:openssl.fork"],
				Version:     props["pqcota:openssl.version"],
				BindingMode: parseBindingMode(props["pqcota:openssl.binding_mode"]),
			}}
		case commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA:
			providerSet := splitCSV(props["pqcota:jca.provider_set"])
			f.RuntimeAxes = &discoveryv1.Finding_Jca{Jca: &discoveryv1.JcaAxes{
				ProviderSet:      providerSet,
				RegistrationMode: parseRegistrationMode(props["pqcota:jca.registration_mode"]),
			}}
			// provider 시그니처 레지스트리 강화(수용 원칙 §2.3 · 프로비저닝 설계 §4.2): FIPS·SLH-DSA 갭.
			f.FipsValidation, f.PqcReadiness = jcaEnrichment(providerSet)
		case commonv1.CryptoRuntime_CRYPTO_RUNTIME_WIN_CNG:
			// CNG는 JCA와 같은 provider 축이다(수용 원칙 §2.1). provider 이름만으로는
			// "이 노드가 ML-DSA를 할 수 있나"에 답할 수 없어(실측: provider 9개가 전부
			// Microsoft 이름) 알고리즘 목록도 함께 파생한다.
			algs := cngAlgorithms(props["pqcota:cng.algorithms"])
			f.RuntimeAxes = &discoveryv1.Finding_Cng{Cng: &discoveryv1.CngAxes{
				ProviderSet: splitCSV(props["pqcota:cng.provider_set"]),
				Algorithms:  algs,
			}}
			f.FipsValidation, f.PqcReadiness = cngEnrichment(algs)
		}

		f.AppKeys = splitCSV(props["pqcota:app_keys"]) // 자산이 어느 앱 것인지(§1.5) — 어느 앱(들)의 크립토인가
		f.Id = findingID(node, c.Name, props)
		out = append(out, f)
	}
	return out, nil
}

// findingID — finding 동일성 정규화 해시(§2.4⑤ dedup 앵커). 노드+컴포넌트+런타임+fork 기반.
func findingID(node, name string, props map[string]string) string {
	key := strings.Join([]string{
		node, name,
		props["pqcota:crypto_runtime"],
		props["pqcota:openssl.fork"],
	}, "|")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func parseCryptoRuntime(s string) commonv1.CryptoRuntime {
	switch s {
	case "openssl":
		return commonv1.CryptoRuntime_CRYPTO_RUNTIME_OPENSSL
	case "jca":
		return commonv1.CryptoRuntime_CRYPTO_RUNTIME_JCA
	case "cng":
		return commonv1.CryptoRuntime_CRYPTO_RUNTIME_WIN_CNG
	default:
		return commonv1.CryptoRuntime_CRYPTO_RUNTIME_UNSPECIFIED
	}
}

// parseDetectionMethod — 문자열(복합 가능, 예 "runtime-introspection+symbol-analysis")에서
// 가장 강한 방법을 택한다. 문자열이 비면 Envelope의 방법으로 폴백.
func parseDetectionMethod(s string, envelope commonv1.DetectionMethod) commonv1.DetectionMethod {
	switch {
	case strings.Contains(s, "runtime-introspection"):
		return commonv1.DetectionMethod_DETECTION_METHOD_RUNTIME_INTROSPECTION
	case strings.Contains(s, "dynamic-trace"):
		return commonv1.DetectionMethod_DETECTION_METHOD_DYNAMIC_TRACE
	case strings.Contains(s, "source"):
		return commonv1.DetectionMethod_DETECTION_METHOD_SOURCE
	case strings.Contains(s, "artifact"):
		return commonv1.DetectionMethod_DETECTION_METHOD_ARTIFACT
	case strings.Contains(s, "symbol-analysis"):
		return commonv1.DetectionMethod_DETECTION_METHOD_SYMBOL_ANALYSIS
	default:
		return envelope
	}
}

func parseBindingMode(s string) commonv1.OpensslBindingMode {
	switch s {
	case "dynamic":
		return commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_DYNAMIC
	case "static":
		return commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_STATIC
	case "dlopen":
		return commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_DLOPEN
	case "vendored":
		return commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_VENDORED
	default:
		return commonv1.OpensslBindingMode_OPENSSL_BINDING_MODE_UNSPECIFIED
	}
}

func parseRegistrationMode(s string) commonv1.JcaRegistrationMode {
	switch s {
	case "static":
		return commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_STATIC
	case "dynamic":
		return commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_DYNAMIC
	case "explicit":
		return commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_EXPLICIT
	default:
		return commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_UNSPECIFIED
	}
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// jcaEnrichment — provider_set을 시그니처 레지스트리와 대조해 fips_validation·pqc_readiness를
// 파생한다(수용 원칙 §2.3 · 프로비저닝 설계 §4.2). SLH-DSA는 JDK 네이티브에 없으므로 갭을 명시한다.
func jcaEnrichment(providers []string) (fips, readiness string) {
	fips = "none"
	hasMLKEM, hasSLHDSA := false, false
	for _, name := range providers {
		if sig, ok := registry.MatchProvider(name, registry.DefaultProviderSignatures); ok {
			if sig.FipsValidation == "140-3" {
				fips = "140-3"
			}
			if sig.Covers("ML-KEM") {
				hasMLKEM = true
			}
			if sig.Covers("SLH-DSA") {
				hasSLHDSA = true
			}
		}
	}
	switch {
	case hasMLKEM && hasSLHDSA:
		readiness = "provider-augmented (all standard algorithms)"
	case hasMLKEM && !hasSLHDSA:
		readiness = "provider-augmented (SLH-DSA gap)"
	default:
		readiness = "unknown"
	}
	return fips, readiness
}

// cngAlgorithms — collector가 property 한 줄로 나른 알고리즘 목록을 계약 타입으로.
//
// 표기는 `이름:종류[:provider|provider]`를 쉼표로 이은 것이다(cng collector의 EncodeAlgorithms).
// 종류를 못 읽으면
// **이름만 살린다** — 종류를 모르는 것이 알고리즘을 못 본 것이 되면 안 된다(§2.6).
func cngAlgorithms(s string) []*discoveryv1.CngAlgorithm {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []*discoveryv1.CngAlgorithm
	for _, part := range strings.Split(s, ",") {
		name, rest, _ := strings.Cut(part, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		class, provs, _ := strings.Cut(rest, ":")
		a := &discoveryv1.CngAlgorithm{Name: name, Class: strings.TrimSpace(class)}
		for _, p := range strings.Split(provs, "|") {
			if p = strings.TrimSpace(p); p != "" {
				a.Providers = append(a.Providers, p)
			}
		}
		out = append(out, a)
	}
	return out
}

// cngEnrichment — 관측된 알고리즘 이름을 PQC 레지스트리와 대조해 readiness를 파생한다(§1.2 —
// 규칙이 한 곳에 있어야 재계산으로 재현된다).
//
// **판정이 아니라 관측의 요약이다.** "이 노드는 위험하다"가 아니라 "이 이름들이 열거됐다"를
// 줄여 적는다(아키텍처 §6 무판단 원칙). 실측이 보인 모양이 정확히 이 갈래였다 — Windows 11
// 26200은 ML-DSA는 열거하고 ML-KEM은 열거하지 않는다.
func cngEnrichment(algs []*discoveryv1.CngAlgorithm) (fips, readiness string) {
	// CNG의 FIPS 모드 여부는 알고리즘 열거로 알 수 없다 — 관측하지 않은 것을 적지 않는다(§2.5).
	fips = "unknown"

	var hasKEM, hasSig bool
	for _, a := range algs {
		pqc, ok := registry.MatchPQC(a.GetName())
		if !ok {
			continue
		}
		switch pqc.Kind {
		case registry.KindKEM:
			hasKEM = true
		case registry.KindSignature:
			hasSig = true
		}
	}
	switch {
	case hasKEM && hasSig:
		readiness = "native (KEM and signature)"
	case hasSig:
		readiness = "native (signature only — no KEM observed)"
	case hasKEM:
		readiness = "native (KEM only — no signature observed)"
	case len(algs) == 0:
		readiness = "unknown" // 알고리즘을 못 봤다. 없다는 뜻이 아니다(§2.6)
	default:
		readiness = "none (only classical algorithms observed)"
	}
	return fips, readiness
}
