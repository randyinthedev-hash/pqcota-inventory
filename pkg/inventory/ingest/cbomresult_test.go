// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package ingest

import "testing"

// 정규화 입력의 판은 본문이 선언한 값이다. 예전에는 1.7 입력도 "1.6"으로 적었다.
func TestCBOMResultKeepsDeclaredSpecVersion(t *testing.T) {
	for _, v := range []string{"1.6", "1.7"} {
		raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"` + v + `","components":[]}`)
		disp, env, _ := ImportCBOM(raw, "n", nil)
		if disp != Accepted {
			t.Fatalf("%s: %v", v, disp)
		}
		res := cbomResult(raw, env)
		if got := res.GetCyclonedxSpecVersion(); got != v {
			t.Errorf("specVersion %s recorded as %q", v, got)
		}
		if string(res.GetCbomCyclonedx()) != string(raw) || res.GetEnvelope() != env {
			t.Errorf("%s: body or envelope changed", v)
		}
	}
}
