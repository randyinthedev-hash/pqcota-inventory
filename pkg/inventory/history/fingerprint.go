// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package history

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
)

// ContentHash — 스냅샷의 **실질 내용** 지문. "같은 상태를 다시 관측한 것인가"를 판정하는 근거다.
// 포함/제외 필드의 근거 표는 인벤토리 설계 §7.3에 있다.
//
// 휘발 필드는 반드시 제외한다 — 관측할 때마다 달라지므로 포함하면 항상 "변화"가 되어
// 중복 억제가 무력해진다:
//   - Finding.derived_from_snapshot_id·ruleset_version (스냅샷마다 다름)
//   - ObservedEdge.observed_count·first_seen·last_seen (관측 빈도·시각)
//
// 반대로 실질 내용(자산 동일성·버전·바인딩·앱·협상 그룹·완전성 갭)은 전부 포함한다.
// 여기서 빠뜨린 필드가 바뀌면 "변화 없음"으로 접혀 이력에서 사라지므로, 필드를 추가할 땐
// 이 함수도 함께 갱신해야 한다.
func ContentHash(s *Snapshot) string {
	h := sha256.New()

	fs := append([]*discoveryv1.Finding(nil), s.Findings...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].GetId() < fs[j].GetId() })
	for _, f := range fs {
		fmt.Fprintf(h, "F|%s|%d|%d|%d|%d|%s|%s|%s|%s|%s\n",
			f.GetId(), f.GetCryptoRuntime(), f.GetUsageContext(), f.GetDetectionMethod(),
			f.GetEvidenceStrength(), f.GetAlgorithm(), f.GetPqcReadiness(),
			f.GetFipsValidation(), f.GetRemediationClass(), sortedJoin(f.GetAppKeys()))
		if o := f.GetOpenssl(); o != nil {
			fmt.Fprintf(h, "  O|%s|%s|%s|%d\n", o.GetLib(), o.GetFork(), o.GetVersion(), o.GetBindingMode())
		}
		if j := f.GetJca(); j != nil {
			// provider_set은 **순서에 의미가 있다**(우선순위 협상, 수용 원칙 §2.2) — 정렬하지 않는다.
			fmt.Fprintf(h, "  J|%s|%s|%s|%d\n", j.GetJdkVendor(), j.GetJdkVersion(),
				strings.Join(j.GetProviderSet(), ","), j.GetRegistrationMode())
		}
		if c := f.GetCng(); c != nil {
			// provider_set은 **관측된 순서 그대로** 담긴 것이라 정렬하지 않는다(그 순서가 우선순위인지는
			// CNG에서 미확인 — 관측을 고치지 않으려고 순서를 보존한다).
			//
			// 알고리즘은 collector가 이미 정렬해 낸다. 여기서 다시 정렬하지 않는 대신 **있는 그대로**
			// 넣는다 — 순서가 흔들리면 그것도 관측이 달라진 것이다.
			var algs []string
			for _, a := range c.GetAlgorithms() {
				algs = append(algs, a.GetName()+":"+a.GetClass()+":"+strings.Join(a.GetProviders(), "|"))
			}
			fmt.Fprintf(h, "  N|%s|%s\n", strings.Join(c.GetProviderSet(), ","), strings.Join(algs, ","))
		}
	}

	es := append([]*discoveryv1.ObservedEdge(nil), s.Edges...)
	sort.Slice(es, func(i, j int) bool { return edgeKey(es[i]) < edgeKey(es[j]) })
	for _, e := range es {
		fmt.Fprintf(h, "E|%s|%s|%s\n", edgeKey(e), e.GetNegotiatedGroup(), e.GetCipher())
	}

	if c := s.Completeness; c != nil {
		var miss []string
		for _, l := range c.GetLayersMissing() {
			miss = append(miss, l.String())
		}
		sort.Strings(miss)
		fmt.Fprintf(h, "C|%s|%s\n", strings.Join(miss, ","), c.GetNote())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// edgeKey — 엣지의 동일성 키(빈도·시각 제외).
func edgeKey(e *discoveryv1.ObservedEdge) string {
	return fmt.Sprintf("%s>%s@%s:%d/%d/%d/%d", e.GetSrcNodeId(), e.GetDstNodeId(), e.GetDstAddr(),
		e.GetPort(), e.GetProtocol(), e.GetRole(), e.GetDetectionMethod())
}

func sortedJoin(ss []string) string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return strings.Join(out, ",")
}

// SnapshotContentFormatV1 — 참조용 지문의 **규격 판**. 해시 알고리즘이 아니라 어떤 필드를 어떤
// 순서로 해시했는지를 가리킨다. 다운스트림이 같은 스냅샷을 같은 규칙으로 만들어 같은 값을 내고,
// 이력이 그 값으로 스냅샷을 찾는다.
//
// **v1은 닫혔다.** 필드를 더하거나 순서를 바꾸면 v2를 새로 만든다. v1을 고쳐 쓰면 이미 저장된
// v1 참조가 같은 규칙으로 다시 계산되지 않는다. TestContentHashV1IsFrozen이 고정 입력의 값으로
// 그것을 잰다.
const SnapshotContentFormatV1 = "pqcota-snapshot-content/v1"

// ContentHashV1 — 참조용 지문. [ContentHash](중복 억제)와 **용도가 다르다.**
//
// 중복 억제는 「같은 상태를 다시 관측했는가」를 묻는다 — 그래서 규칙 판을 뺀다. 참조는 「어느
// 스냅샷 상태에서 나온 조치인가」를 묻는다 — 규칙 판이 다르면 다른 상태다. 두 물음을 한 함수에
// 섞지 않는다. 다만 v1이 생긴 뒤로 이력의 중복 억제도 이 값으로 접는다(pg.go·history.go) — 옛
// 지문으로 접으면 v1 열이 빈 옛 행이 재사용되어 v1 참조가 영원히 찾히지 않기 때문이다.
//
// ContentHash와 다른 점:
//   - RulesetVersion을 넣는다.
//   - ExcludedByScope를 넣는다. 정책의 **결과인 제외 수**다. 어떤 정책인지까지 증명하지는 않는다.
//   - 엣지를 안정 필드 전부(EdgeIdentity와 같은 필드)로 정렬하고, app_key·app_key_kind를 넣는다.
//   - Completeness.layers_covered를 넣는다. 무엇을 봤는지가 빠지면 「못 봤다」와 「안 봤다」가
//     같은 지문이 된다.
//   - 필드마다 NUL로 끊는다. 구분자가 값에 섞이지 않게.
func ContentHashV1(s *Snapshot) string {
	h := sha256.New()
	w := func(parts ...string) {
		for _, p := range parts {
			h.Write([]byte(p))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	w("V", SnapshotContentFormatV1)
	w("R", s.RulesetVersion)
	w("X", fmt.Sprint(s.ExcludedByScope))

	fs := append([]*discoveryv1.Finding(nil), s.Findings...)
	sort.Slice(fs, func(i, j int) bool { return fs[i].GetId() < fs[j].GetId() })
	for _, f := range fs {
		w("F", f.GetId(), f.GetCryptoRuntime().String(), f.GetUsageContext().String(),
			f.GetDetectionMethod().String(), f.GetEvidenceStrength().String(), f.GetAlgorithm(),
			f.GetPqcReadiness(), f.GetFipsValidation(), f.GetRemediationClass(), sortedJoin(f.GetAppKeys()))
		if o := f.GetOpenssl(); o != nil {
			w("O", o.GetLib(), o.GetFork(), o.GetVersion(), o.GetBindingMode().String())
		}
		if j := f.GetJca(); j != nil {
			w("J", j.GetJdkVendor(), j.GetJdkVersion(), strings.Join(j.GetProviderSet(), ","), j.GetRegistrationMode().String())
		}
		if c := f.GetCng(); c != nil {
			var algs []string
			for _, a := range c.GetAlgorithms() {
				algs = append(algs, a.GetName()+":"+a.GetClass()+":"+strings.Join(a.GetProviders(), "|"))
			}
			w("N", strings.Join(c.GetProviderSet(), ","), strings.Join(algs, ","))
		}
	}

	es := append([]*discoveryv1.ObservedEdge(nil), s.Edges...)
	sort.Slice(es, func(i, j int) bool { return edgeIdentityV1(es[i]) < edgeIdentityV1(es[j]) })
	for _, e := range es {
		w("E", e.GetSrcNodeId(), e.GetDstNodeId(), e.GetDstAddr(), fmt.Sprint(e.GetPort()),
			e.GetProtocol().String(), e.GetRole().String(), e.GetDetectionMethod().String(),
			e.GetNegotiatedGroup(), e.GetCipher(), e.GetAppKey(), e.GetAppKeyKind())
	}

	if c := s.Completeness; c != nil {
		var cov, miss []string
		for _, l := range c.GetLayersCovered() {
			cov = append(cov, l.String())
		}
		for _, l := range c.GetLayersMissing() {
			miss = append(miss, l.String())
		}
		sort.Strings(cov)
		sort.Strings(miss)
		w("C", strings.Join(cov, ","), strings.Join(miss, ","), c.GetNote())
	}
	return hex.EncodeToString(h.Sum(nil))
}

// edgeIdentityV1 — v1이 엣지를 정렬하는 키. normalize.EdgeIdentity와 같은 필드·같은 순서다.
// 여기 따로 적는 것은 v1을 normalize의 변경에서 떼어 두기 위해서다 — 저쪽이 바뀌어도 v1은
// 닫혀 있어야 한다.
func edgeIdentityV1(e *discoveryv1.ObservedEdge) string {
	return strings.Join([]string{
		e.GetSrcNodeId(), e.GetDstNodeId(), e.GetDstAddr(), fmt.Sprint(e.GetPort()),
		e.GetProtocol().String(), e.GetRole().String(), e.GetDetectionMethod().String(),
		e.GetNegotiatedGroup(), e.GetCipher(), e.GetAppKey(), e.GetAppKeyKind(),
	}, "|")
}
