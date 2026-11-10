// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

// Group — 화면에서 한 줄로 보일 위치들. 변환 결과는 합치지 않는다 — 묶기는 보여 줄 때만 한다.
type Group struct {
	Locations []Location // 묶인 위치 전부. 원본 포인터를 모두 보여 줄 수 있게 위치를 그대로 둔다
}

// GroupLocations — 한 근거 항목 안의 위치를 화면용으로 묶는다(계약 검토 §3 끝). 다른 항목의 위치는 넘기지 않는다.
//
// 두 위치는 다음을 모두 만족할 때만 묶는다.
//   - 좌표의 종류가 같다: 정규화한 값과 보고값을 섞어 비교하지 않는다.
//   - 줄: 둘 다 정규화한 값이 같거나, 둘 다 보고값만 있고 같은 규칙이 만들었으며 보고값이 같다.
//     기준을 모르는 보고값은 같은 규칙일 때만 같은 기준이라고 볼 수 있다.
//   - 열: 둘 다 없거나, 둘 다 정규화했고 단위가 같은 알려진 값이며 같거나, 같은 규칙의 같은 보고값이다.
//   - 경로: 같은 종류(정규화/보고)끼리 문자열이 같다.
//
// 결과 순서는 각 묶음의 첫 위치가 나온 순서다(결정론).
func GroupLocations(locs []Location) []Group {
	var out []Group
	for _, l := range locs {
		placed := false
		for gi := range out {
			if sameDisplayed(out[gi].Locations[0], l) {
				out[gi].Locations = append(out[gi].Locations, l)
				placed = true
				break
			}
		}
		if !placed {
			out = append(out, Group{Locations: []Location{l}})
		}
	}
	return out
}

func sameDisplayed(a, b Location) bool {
	sameRule := a.Rule == b.Rule
	if !sameLine(a, b, sameRule) || !sameColumn(a, b, sameRule) {
		return false
	}
	aNorm, bNorm := a.Normalized.Line != nil, b.Normalized.Line != nil
	if aNorm && bNorm {
		return a.Normalized.Path == b.Normalized.Path
	}
	return a.Reported.Path == b.Reported.Path
}

func sameLine(a, b Location, sameRule bool) bool {
	an, bn := a.Normalized.Line, b.Normalized.Line
	switch {
	case an != nil && bn != nil:
		return *an == *bn
	case an != nil || bn != nil:
		return false // 한쪽만 정규화됐다 — 종류가 다르다
	}
	// 둘 다 보고값만(또는 줄 없음).
	return sameRule && eqPtr(a.Reported.Line, b.Reported.Line)
}

func sameColumn(a, b Location, sameRule bool) bool {
	ar, br := a.Reported.Column, b.Reported.Column
	if ar == nil && br == nil {
		return true
	}
	an, bn := a.Normalized.Column, b.Normalized.Column
	if an != nil && bn != nil && a.ColumnUnit == b.ColumnUnit && a.ColumnUnit != "" && a.ColumnUnit != "unknown" {
		return *an == *bn
	}
	if (an != nil) != (bn != nil) {
		return false
	}
	return sameRule && eqPtr(ar, br)
}

func eqPtr(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
