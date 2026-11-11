// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package sourceevidence

import (
	"embed"
	"fmt"
	"sort"
)

// 내장 프리셋 — 같은 `pqcota-source-map/v1` 설정이다. 어느 도구의 어느 판 출력으로 확인했는지는 아래 목록에 적는다.
// 설정 내용을 바꾸면 revision을 올린다(같은 판의 내용을 바꾸지 않는다 — 원문 해시가 결과에 남는다).
//
//go:embed presets/*.json
var presetFS embed.FS

// Preset — 내장 프리셋 하나와 그 출처.
type Preset struct {
	ID           string
	Revision     string
	VerifiedWith string // 이 출력으로 확인했다. 다른 판에서도 맞는다고 약속하지 않는다
	Note         string
}

// presetInfo — 확인한 도구·판. 줄의 시작 기준은 예제 소스와 대조해 1로 두고, 열은 기준·단위를 확인하지 못해 unknown이다(설계 §5.2).
var presetInfo = map[string]Preset{
	"cdxgen-dotnet-sourcelocation": {
		VerifiedWith: "cdxgen 13.7.0, .NET 8 project (dosai analysis inside cdxgen)",
		Note:         "reads cdx:crypto:sourceLocation; one component can carry several locations",
	},
	"dosai-cyclonedx-location": {
		VerifiedWith: "dosai 5.0.0.0 CycloneDX output, .NET 8 project",
		Note:         "reads dosai:location on cryptographic-asset components; operation components (type data) are not read",
	},
}

// Presets — 내장 프리셋 목록(ID 순).
func Presets() []Preset {
	out := make([]Preset, 0, len(presetInfo))
	for id := range presetInfo {
		lm, err := LoadPreset(id)
		if err != nil {
			panic(err) // 내장 파일은 시험이 검증한다
		}
		p := presetInfo[id]
		p.ID, p.Revision = id, lm.Revision()
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LoadPreset — 내장 프리셋을 읽는다.
func LoadPreset(id string) (*LoadedMap, error) {
	if _, ok := presetInfo[id]; !ok {
		return nil, fmt.Errorf("no preset %q", id)
	}
	raw, err := presetFS.ReadFile("presets/" + id + ".json")
	if err != nil {
		return nil, err
	}
	lm, err := newLoadedMap("preset", raw)
	if err != nil {
		return nil, fmt.Errorf("preset %s: %w", id, err)
	}
	if lm.ID() != id {
		return nil, fmt.Errorf("preset file %s declares id %q", id, lm.ID())
	}
	return lm, nil
}
