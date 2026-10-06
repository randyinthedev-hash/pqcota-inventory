// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Package resultio — 회수된 CollectionResult를 파일에서 읽어 들이는 **공식 디코더**.
//
// 한 파일에 결과가 하나일 수도, 여럿일 수도 있다. jvm attach 경로는 노드에서 돌던 JVM마다
// 한 건씩 내므로 한 파일에 여러 결과가 담긴다. 그래서 형식이 둘이다 — 들여쓴 단일 객체와
// JSON Lines(한 줄에 하나). **판별은 확장자가 아니라 내용으로 한다.**
//
// 확장자를 믿고 `.json`을 단일 객체로만 읽으면 JVM이 둘 이상인 노드의 결과가 통째로 사라진다.
// 실제로 pqcota-discover-view가 그렇게 읽어, 그 노드의 JCA 자산이 화면에서 빠졌다. 게다가
// JVM이 하나일 때는 한 줄짜리 JSON Lines가 단일 객체로도 읽히는 탓에, 같은 코드가 노드마다
// 되기도 하고 안 되기도 했다.
//
// 소비자마다 파서를 따로 적으면 그중 하나는 반드시 다르게 읽는다. 그래서 리포 밖에서도 쓰라고
// 공개해 둔다.
//
// # 파일 이름 규약
//
// 내는 쪽은 결과가 여럿일 수 있는 자리에 `.jsonl`을, 반드시 하나인 자리에 `.json`을 쓴다.
// 확장자는 사람과 외부 도구에게 주는 예고이지 이 디코더의 판단 근거가 아니다.
package resultio

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Flaw — 읽어 내지 못한 입력 한 건. 무엇을 왜 못 읽었는지 남긴다.
//
// **버리지 않고 돌려주는 것이 요점이다.** 알리지 않고 건너뛰면 빠진 자산이 화면에서 "없음"과
// 구별되지 않는다(§2.6 — 못 본 것은 부재가 아니다).
type Flaw struct {
	Path string // 파일 경로. [Decode]를 직접 부른 경우는 빈 값이다
	Line int    // JSON Lines에서 몇 번째 줄인가. 파일 전체가 문제면 0이다
	Err  error
}

func (f Flaw) Error() string {
	where := f.Path
	if where == "" {
		where = "input"
	}
	if f.Line > 0 {
		where = fmt.Sprintf("%s line %d", where, f.Line)
	}
	return fmt.Sprintf("%s: %v", where, f.Err)
}

func (f Flaw) Unwrap() error { return f.Err }

// ErrEmpty — 파일은 열렸는데 결과가 한 건도 없을 때. **손상과 구분해서** 내보낸다.
// 빈 파일은 낸 쪽이 아무것도 못 냈다는 뜻이고, 손상은 낸 것이 도중에 망가졌다는 뜻이라
// 뒤이어 볼 자리가 다르다. 소비자가 [errors.Is]로 갈라 볼 수 있게 공개한다.
var ErrEmpty = errors.New("no CollectionResult in it")

// Decode — 바이트에서 CollectionResult를 뽑는다. 확장자를 보지 않는다.
//
// 파일 전체를 단일 객체로 먼저 시도하고, 실패하면 JSON Lines로 줄마다 읽는다. **이 순서라야**
// 들여쓴 단일 객체를 줄 단위로 잘못 쪼개지 않는다.
//
// 읽어 낸 결과와 읽지 못한 줄을 함께 돌려준다. 둘 중 무엇을 실패로 볼지는 부르는 쪽이 정한다 —
// 적재 관문은 한 줄이라도 어긋나면 멈추고, 조회용 뷰는 알리고 계속한다.
func Decode(b []byte) ([]*discoveryv1.CollectionResult, []Flaw) {
	if res := (&discoveryv1.CollectionResult{}); protojson.Unmarshal(b, res) == nil {
		return []*discoveryv1.CollectionResult{res}, nil
	}
	var out []*discoveryv1.CollectionResult
	var flaws []Flaw
	for i, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		res := &discoveryv1.CollectionResult{}
		if err := protojson.Unmarshal([]byte(line), res); err != nil {
			flaws = append(flaws, Flaw{Line: i + 1, Err: err})
			continue
		}
		out = append(out, res)
	}
	return out, flaws
}

// LoadDir — 결과 디렉터리에서 `*.json`과 `*.jsonl`을 모두 읽는다.
//
// 읽는 순서는 `*.json` 묶음 다음에 `*.jsonl` 묶음이고, 각 묶음은 이름순이다([filepath.Glob]이
// 정렬해 돌려준다). 같은 입력이면 같은 순서가 나와야 적재 결과를 회차끼리 비교할 수 있다.
//
// 열지 못한 파일, 해독하지 못한 줄, 결과가 한 건도 없는 파일을 모두 [Flaw]로 돌려준다.
func LoadDir(dir string) ([]*discoveryv1.CollectionResult, []Flaw) {
	var paths []string
	for _, g := range []string{"*.json", "*.jsonl"} {
		m, _ := filepath.Glob(filepath.Join(dir, g))
		paths = append(paths, m...)
	}

	var out []*discoveryv1.CollectionResult
	var flaws []Flaw
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			flaws = append(flaws, Flaw{Path: p, Err: err})
			continue
		}
		res, fl := Decode(b)
		for i := range fl {
			fl[i].Path = p
		}
		flaws = append(flaws, fl...)
		if len(res) == 0 && len(fl) == 0 {
			// 빈 파일·공백뿐인 파일. 낸 쪽이 아무것도 못 냈다는 뜻이라 그대로 알린다.
			flaws = append(flaws, Flaw{Path: p, Err: ErrEmpty})
		}
		out = append(out, res...)
	}
	return out, flaws
}
