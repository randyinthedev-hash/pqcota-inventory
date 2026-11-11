// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// JCA 식별 1단계(규칙 판 v4). 배포본 하나(finding 하나)에 설정 변형 목록(instances)을 싣는다.
//
// 수집기가 배포본마다 결과 하나를 내고, 그 안의 JVM을 변형으로 묶어 `pqcota:jca.instances`로 나른다.
// 정규화는 변형마다 강화 값을 계산하고 finding 한 장의 값을 정한다. **아무것도 버리지 않고, 가장 나쁜 값으로
// 접지 않는다.**

// jcaInstanceProp — `pqcota:jca.instances` 배열의 원소(계약 README의 속성 표).
type jcaInstanceProp struct {
	VariantKey         string `json:"variantKey"`
	JavaHome           string `json:"javaHome"`
	SecurityProperties struct {
		Set   bool   `json:"set"`
		Value string `json:"value"`
	} `json:"securityProperties"`
	ChainObserved bool     `json:"chainObserved"`
	ProviderSet   []string `json:"providerSet"`
	PqcServices   string   `json:"pqcServices"`
	ModeCounts    []struct {
		Mode  string `json:"mode"`
		Count uint32 `json:"count"`
	} `json:"modeCounts"`
	Count uint32 `json:"count"`
}

var fullSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// variesValue — 변형끼리 값이 다를 때 finding 한 장에 적는 사실. 하나로 접지 않는다.
func variesValue(n int) string { return fmt.Sprintf("varies (%d variants)", n) }

// unobservedValue — 체인을 보지 못한 변형의 강화 값. 없다는 뜻이 아니다(§2.6).
const unobservedValue = "unknown"

// parseJcaInstances — 속성을 계약 타입으로. 꼴이 틀리면 거부한다(서명된 수집기 출력이 깨졌다는 뜻이다).
// 결과는 variant_key 순, mode_counts는 모드 열거값 순이다. 입력 순서와 무관하다.
func parseJcaInstances(raw string) ([]*discoveryv1.JcaInstance, error) {
	var in []jcaInstanceProp
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil, err
	}
	if len(in) == 0 {
		return nil, fmt.Errorf("no instances")
	}
	seen := map[string]bool{}
	var out []*discoveryv1.JcaInstance
	for i, p := range in {
		if !fullSHA256.MatchString(p.VariantKey) {
			return nil, fmt.Errorf("instance %d: variantKey must be a full lowercase SHA-256", i)
		}
		if seen[p.VariantKey] {
			return nil, fmt.Errorf("instance %d: variantKey %s appears twice", i, p.VariantKey[:12])
		}
		seen[p.VariantKey] = true
		if !p.ChainObserved && len(p.ProviderSet) > 0 {
			return nil, fmt.Errorf("instance %d: a chain is given although chainObserved is false", i)
		}
		counts := map[commonv1.JcaRegistrationMode]uint32{}
		var sum uint32
		for _, m := range p.ModeCounts {
			mode, ok := registrationModeOf(m.Mode)
			if !ok {
				return nil, fmt.Errorf("instance %d: unknown mode %q", i, m.Mode)
			}
			counts[mode] += m.Count
			sum += m.Count
		}
		if p.Count == 0 || sum != p.Count {
			return nil, fmt.Errorf("instance %d: count %d does not equal the sum of modeCounts %d", i, p.Count, sum)
		}
		inst := &discoveryv1.JcaInstance{
			VariantKey:            p.VariantKey,
			JavaHome:              p.JavaHome,
			SecurityPropertiesSet: p.SecurityProperties.Set,
			SecurityProperties:    p.SecurityProperties.Value,
			ChainObserved:         p.ChainObserved,
			ProviderSet:           p.ProviderSet,
			Count:                 p.Count,
		}
		var modes []commonv1.JcaRegistrationMode
		for m, c := range counts {
			if c > 0 {
				modes = append(modes, m)
			}
		}
		sort.Slice(modes, func(a, b int) bool { return modes[a] < modes[b] })
		for _, m := range modes {
			inst.ModeCounts = append(inst.ModeCounts, &discoveryv1.JcaModeCount{Mode: m, Count: counts[m]})
		}
		if len(modes) == 1 {
			inst.RegistrationMode = modes[0]
		}
		if p.ChainObserved {
			inst.FipsValidation, inst.PqcReadiness = jcaEnrichment(p.ProviderSet, jcaServices(p.PqcServices))
		} else {
			inst.FipsValidation, inst.PqcReadiness = unobservedValue, unobservedValue
		}
		out = append(out, inst)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].GetVariantKey() < out[b].GetVariantKey() })
	return out, nil
}

// summarizeInstances — finding 한 장의 값.
//   - provider_set: 모든 변형을 관측했고 체인이 하나면 그 체인, 아니면 빈 값(체인은 instances에 있다).
//   - readiness·FIPS: 모든 변형이 같으면 그 값, 다르면 「varies (N variants)」. 미관측 변형은 unknown으로 센다.
//   - registration_mode: 모든 JVM이 같은 모드면 그 값, 섞이면 UNSPECIFIED.
func summarizeInstances(insts []*discoveryv1.JcaInstance) (chain []string, mode commonv1.JcaRegistrationMode, fips, readiness string) {
	chains := map[string][]string{}
	unobserved := false
	modes := map[commonv1.JcaRegistrationMode]bool{}
	fipsSet, readySet := map[string]bool{}, map[string]bool{}
	for _, in := range insts {
		if in.GetChainObserved() {
			b, _ := json.Marshal(in.GetProviderSet())
			chains[string(b)] = in.GetProviderSet()
		} else {
			unobserved = true
		}
		for _, mc := range in.GetModeCounts() {
			modes[mc.GetMode()] = true
		}
		fipsSet[in.GetFipsValidation()] = true
		readySet[in.GetPqcReadiness()] = true
	}
	if !unobserved && len(chains) == 1 {
		for _, c := range chains {
			chain = c
		}
	}
	if len(modes) == 1 {
		for m := range modes {
			mode = m
		}
	}
	fips, readiness = variesValue(len(insts)), variesValue(len(insts))
	if len(fipsSet) == 1 {
		fips = insts[0].GetFipsValidation()
	}
	if len(readySet) == 1 {
		readiness = insts[0].GetPqcReadiness()
	}
	return chain, mode, fips, readiness
}

func registrationModeOf(s string) (commonv1.JcaRegistrationMode, bool) {
	switch s {
	case "":
		return commonv1.JcaRegistrationMode_JCA_REGISTRATION_MODE_UNSPECIFIED, true
	case "static", "dynamic", "explicit":
		return parseRegistrationMode(s), true
	}
	return 0, false
}

// jcaFindingIDFormat — 새 JCA finding id 형식의 판. 나중에 꼴을 바꿀 때 판을 가르는 자리다.
const jcaFindingIDFormat = "pqcota-finding-id/jca-1"

// jcaFindingID — app_key_kind가 있는 새 JCA 입력의 id. 해시 입력 **전체**를 필드 순서가 고정된 구조로
// 직렬화한다. 옛 findingID처럼 `|`로 이으면 키 값(JAR 경로 등)에 `|`가 들어갈 때 필드 경계가 모호해진다.
// 이 직렬화가 보존하는 것은 새 형식 안의 필드 경계다. 옛 이음과 바이트가 다르다는 보장까지 하지는 않는다.
func jcaFindingID(node, name, runtime, kind string) string {
	b, _ := json.Marshal(struct {
		Format     string `json:"format"`
		Node       string `json:"node"`
		Component  string `json:"component"`
		Runtime    string `json:"runtime"`
		AppKeyKind string `json:"app_key_kind"`
	}{jcaFindingIDFormat, node, name, runtime, kind})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
