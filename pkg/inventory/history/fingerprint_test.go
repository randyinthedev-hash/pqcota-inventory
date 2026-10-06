// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

package history_test

import (
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// CNG 축이 바뀌면 **변화로 잡혀야 한다**.
//
// ContentHash가 openssl·jca만 보고 있었다(v0.6.0에서 CNG를 더하며 빠뜨렸다). 그 상태에서는
// 서드파티 provider가 깔려 provider_set이 달라져도 "변화 없음"으로 접혀 이력에서 사라진다 —
// 이 함수의 주석이 경고하는 바로 그 자리다.
func TestContentHashCoversCngAxes(t *testing.T) {
	snap := func(providers []string, algs []*discoveryv1.CngAlgorithm) *history.Snapshot {
		return &history.Snapshot{Findings: []*discoveryv1.Finding{{
			Id:            "f1",
			CryptoRuntime: commonv1.CryptoRuntime_CRYPTO_RUNTIME_WIN_CNG,
			RuntimeAxes: &discoveryv1.Finding_Cng{Cng: &discoveryv1.CngAxes{
				ProviderSet: providers, Algorithms: algs,
			}},
		}}}
	}
	base := snap([]string{"Microsoft Primitive Provider"}, []*discoveryv1.CngAlgorithm{
		{Name: "ML-DSA", Class: "signature", Providers: []string{"Microsoft Primitive Provider"}}})

	for name, other := range map[string]*history.Snapshot{
		"one provider was added": snap([]string{"Microsoft Primitive Provider", "Vendor KSP"},
			[]*discoveryv1.CngAlgorithm{{Name: "ML-DSA", Class: "signature", Providers: []string{"Microsoft Primitive Provider"}}}),
		"an algorithm disappeared": snap([]string{"Microsoft Primitive Provider"}, nil),
		"the serving provider changed": snap([]string{"Microsoft Primitive Provider"},
			[]*discoveryv1.CngAlgorithm{{Name: "ML-DSA", Class: "signature", Providers: []string{"Vendor KSP"}}}),
	} {
		if history.ContentHash(base) == history.ContentHash(other) {
			t.Errorf("%s, yet the fingerprint is the same — the change vanishes from the history", name)
		}
	}
	// 같은 관측이면 같아야 한다(중복 억제가 무력해지지 않게).
	same := snap([]string{"Microsoft Primitive Provider"}, []*discoveryv1.CngAlgorithm{
		{Name: "ML-DSA", Class: "signature", Providers: []string{"Microsoft Primitive Provider"}}})
	if history.ContentHash(base) != history.ContentHash(same) {
		t.Error("the same observation gives a different fingerprint — snapshots pile up with no change")
	}
}
