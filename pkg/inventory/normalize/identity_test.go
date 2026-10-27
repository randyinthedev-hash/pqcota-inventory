// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 한 노드에 같은 파일 이름의 OpenSSL이 둘 이상일 때의 식별(v0.10.6).
//
// 컴포넌트 이름은 파일 이름뿐이다. 경로를 id에 넣기 전에는 시스템의 libssl.so.3과 앱이 번들한
// libssl.so.3이 한 id가 되어, 정규화가 하나만 남기고 원인을 「수집기끼리 다르다」로 적었다.

type sslComp struct {
	path, version, app string // path가 비면 경로를 모르는 입력(외부 CBOM 등)
}

func sslResult(collector string, at int64, cs ...sslComp) *discoveryv1.CollectionResult {
	type prop struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	type comp struct {
		Type       string `json:"type"`
		Name       string `json:"name"`
		Properties []prop `json:"properties"`
	}
	var comps []comp
	for _, c := range cs {
		props := []prop{
			{"pqcota:crypto_runtime", "openssl"}, {"pqcota:detection_method", "runtime-introspection"},
			{"pqcota:openssl.lib", "libssl"}, {"pqcota:openssl.fork", "openssl"},
			{"pqcota:openssl.version", c.version}, {"pqcota:app_keys", c.app},
		}
		if c.path != "" {
			props = append(props, prop{"pqcota:openssl.path", c.path})
		}
		comps = append(comps, comp{"cryptographic-asset", "libssl.so.3", props})
	}
	b, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps})
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{CollectorId: collector, TargetNodeId: "n1",
			CollectedAt: timestamppb.New(time.Unix(at, 0))},
		CbomCyclonedx: b,
	}
}

func normalizeOne(t *testing.T, rs ...*discoveryv1.CollectionResult) *history.Snapshot {
	t.Helper()
	snap, err := normalize.Normalize(rs, "s:n1", "n1", normalize.RulesetVersion, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// 경로가 다르고 파일 이름이 같은 두 설치본은 둘로 남는다. 판·앱·경로 어느 것도 잃지 않는다.
func TestSameFileNameTwoPathsStayTwo(t *testing.T) {
	snap := normalizeOne(t, sslResult("openssl-collector", 1,
		sslComp{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "3.0.13", "nginx.service"},
		sslComp{"/opt/pay/lib/libssl.so.3", "3.5.5", "pay.service"}))
	if len(snap.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (one per installation)", len(snap.Findings))
	}
	got := map[string]string{}
	for _, f := range snap.Findings {
		got[f.GetOpenssl().GetPath()] = f.GetOpenssl().GetVersion() + " " + strings.Join(f.GetAppKeys(), ",")
	}
	if got["/usr/lib/x86_64-linux-gnu/libssl.so.3"] != "3.0.13 nginx.service" || got["/opt/pay/lib/libssl.so.3"] != "3.5.5 pay.service" {
		t.Errorf("installations lost or mixed: %v", got)
	}
	if n := snap.Completeness.GetNote(); n != "" {
		t.Errorf("two distinct installations are not a conflict, yet the note says %q", n)
	}
}

// 경로가 없는 입력의 id는 v0.10.5와 같다(node|이름|런타임|fork). 옛 원본을 다시 정규화하거나
// 외부 CBOM을 받아도 id가 흔들리지 않는다.
func TestPathlessIDUnchanged(t *testing.T) {
	snap := normalizeOne(t, sslResult("external", 1, sslComp{"", "3.0.13", ""}))
	sum := sha256.Sum256([]byte("n1|libssl.so.3|openssl|openssl"))
	if got, want := snap.Findings[0].GetId(), hex.EncodeToString(sum[:]); got != want {
		t.Errorf("a path-less finding changed its id: %s, want %s", got, want)
	}
}

// 같은 경로에서 판만 바뀌면 같은 자산이다. diff에 「없어짐·추가」가 아니라 「바뀜」으로 나온다.
func TestSamePathNewVersionIsAChange(t *testing.T) {
	const p = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	a := normalizeOne(t, sslResult("openssl-collector", 1, sslComp{p, "3.0.13", "nginx.service"}))
	b := normalizeOne(t, sslResult("openssl-collector", 2, sslComp{p, "3.0.15", "nginx.service"}))
	if a.Findings[0].GetId() != b.Findings[0].GetId() {
		t.Fatal("a version change at the same path produced a new identity")
	}
	a.CreatedAt, b.CreatedAt = time.Unix(1, 0), time.Unix(2, 0)
	out := inventory.RenderDiff(a, b)
	if !strings.Contains(out, "changed 1") || strings.Contains(out, "added") || strings.Contains(out, "removed") {
		t.Errorf("want one change and no add/remove:\n%s", out)
	}
}

// 경로가 없는 입력과 경로가 있는 관측이 한 노드에 같은 파일 이름으로 함께 오면, 둘 다 남기고 알린다.
// 같은 설치본을 두 입력이 각각 말한 것인지 다른 설치본인지는 경로 없는 쪽만으로 가를 수 없다.
func TestPathlessAndObservedBothKeptAndNoted(t *testing.T) {
	snap := normalizeOne(t,
		sslResult("external", 1, sslComp{"", "3.0.13", ""}),
		sslResult("openssl-collector", 2, sslComp{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "3.0.13", "nginx.service"}))
	if len(snap.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (neither merged nor dropped)", len(snap.Findings))
	}
	if n := snap.Completeness.GetNote(); !strings.Contains(n, "has no path") {
		t.Errorf("the possible double report is not noted: %q", n)
	}
	// 경로 있는 관측만 있으면 알리지 않는다 — 늘 뜨는 알림은 읽히지 않는다.
	only := normalizeOne(t, sslResult("openssl-collector", 2, sslComp{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "3.0.13", "nginx.service"}))
	if n := only.Completeness.GetNote(); n != "" {
		t.Errorf("nothing overlaps, yet the note says %q", n)
	}
}

// 한 수집기가 한 id에 다른 내용을 보고하면, 「수집기끼리 다르다」라고도, 「두 자산」이라고도 단정하지 않는다.
// 확인된 사실(한 수집기, 한 id, 다른 내용, 최근 것을 남김)만 적는다.
func TestSameCollectorConflictIsStatedNeutrally(t *testing.T) {
	snap := normalizeOne(t, sslResult("external", 1, sslComp{"", "3.0.13", "a"}, sslComp{"", "3.5.5", "b"}))
	n := snap.Completeness.GetNote()
	if strings.Contains(n, "differs between collectors") || strings.Contains(n, "two different assets") {
		t.Errorf("the note asserts a cause it cannot know: %q", n)
	}
	if !strings.Contains(n, "external reported different content for one identity; kept the most recent") {
		t.Errorf("the note does not state what happened: %q", n)
	}
}

// 같은 설치본을 다른 시점에 본 두 결과를 한 번에 정규화하면(결과 디렉터리에 두 번의 수집), 최근 것이
// 남고 노트는 중립 문구다. 이 경우가 「두 자산」이 아니라는 것이 위 문구를 중립으로 둔 까닭이다.
func TestSamePathTwoTimesInOneBatch(t *testing.T) {
	const p = "/usr/lib/x86_64-linux-gnu/libssl.so.3"
	snap := normalizeOne(t,
		sslResult("openssl-collector", 2, sslComp{p, "3.0.15", "nginx.service"}),
		sslResult("openssl-collector", 1, sslComp{p, "3.0.13", "nginx.service"}))
	if len(snap.Findings) != 1 || snap.Findings[0].GetOpenssl().GetVersion() != "3.0.15" {
		t.Fatalf("want the one installation at its latest version, got %d findings: %v", len(snap.Findings), snap.Findings)
	}
	if n := snap.Completeness.GetNote(); !strings.Contains(n, "reported different content for one identity; kept the most recent") {
		t.Errorf("note: %q", n)
	}
}
