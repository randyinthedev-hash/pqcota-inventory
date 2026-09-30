package resultio_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/resultio"
)

// Decode는 단일 객체(compact·multiline)와 JSON Lines를 모두 감당해야 한다.
// jvm attach 경로가 노드당 JVM 여럿을 JSON Lines로 내므로 후자가 필수다.

const oneCompact = `{"envelope":{"targetNodeId":"n1"},"rawFormat":"x"}`

const oneMultiline = `{
  "envelope": {"targetNodeId": "n1"},
  "rawFormat": "x"
}`

// JSON Lines — 한 줄에 하나. 빈 줄은 건너뛴다.
const manyLines = `{"envelope":{"targetNodeId":"jvm-a"},"rawFormat":"x"}

{"envelope":{"targetNodeId":"jvm-b"},"rawFormat":"x"}
`

func TestDecodeSingleCompact(t *testing.T) {
	got, flaws := resultio.Decode([]byte(oneCompact))
	if len(got) != 1 || got[0].GetEnvelope().GetTargetNodeId() != "n1" {
		t.Fatalf("decoding a single compact object failed: %+v", got)
	}
	if len(flaws) != 0 {
		t.Errorf("sound input was reported as flawed: %v", flaws)
	}
}

// ★ pretty-print된 단일 객체는 줄별로는 안 깨진다 — 단일 시도가 JSON Lines보다 먼저여야 한다.
func TestDecodeSingleMultiline(t *testing.T) {
	got, flaws := resultio.Decode([]byte(oneMultiline))
	if len(got) != 1 || got[0].GetEnvelope().GetTargetNodeId() != "n1" {
		t.Fatalf("decoding a single multiline object failed (it may have been split per line): %+v", got)
	}
	if len(flaws) != 0 {
		t.Errorf("sound input was reported as flawed: %v", flaws)
	}
}

func TestDecodeLines(t *testing.T) {
	got, flaws := resultio.Decode([]byte(manyLines))
	if len(got) != 2 {
		t.Fatalf("JSON Lines must give 2 (blank lines excluded): %d", len(got))
	}
	if got[0].GetEnvelope().GetTargetNodeId() != "jvm-a" || got[1].GetEnvelope().GetTargetNodeId() != "jvm-b" {
		t.Errorf("JSON Lines order or content mismatch: %+v", got)
	}
	if len(flaws) != 0 {
		t.Errorf("sound input was reported as flawed: %v", flaws)
	}
}

// ★ 못 읽은 줄을 **버리지 않고 돌려준다.** 예전에는 알리지 않고 건너뛰어서, 손상된 결과가
// 처음부터 없었던 것과 구별되지 않았다(§2.6).
func TestDecodeReportsBadLines(t *testing.T) {
	mixed := `{"envelope":{"targetNodeId":"ok"},"rawFormat":"x"}
{"not":"a collection result but still json"}
plain garbage
`
	got, flaws := resultio.Decode([]byte(mixed))
	var sawOK bool
	for _, r := range got {
		if r.GetEnvelope().GetTargetNodeId() == "ok" {
			sawOK = true
		}
	}
	if !sawOK {
		t.Errorf("the valid first line was lost: %+v", got)
	}
	// protojson은 알 수 없는 필드에 엄격해 2·3번째 줄은 둘 다 실패한다.
	if len(flaws) != 2 {
		t.Fatalf("the 2 unreadable lines must be reported: %v", flaws)
	}
	if flaws[0].Line != 2 || flaws[1].Line != 3 {
		t.Errorf("line numbers are off: %v", flaws)
	}
}

// LoadDir은 두 확장자를 모두 읽는다. 노드 하나가 `.json`과 `.jsonl`을 함께 낼 수 있다
// (OpenSSL은 단일 객체, JVM attach는 JSON Lines).
func TestLoadDirReadsBothExtensions(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "node-a-openssl.json", oneCompact)
	write(t, dir, "node-a-jca.jsonl", manyLines)

	got, flaws := resultio.LoadDir(dir)
	if len(flaws) != 0 {
		t.Fatalf("a sound directory was reported as flawed: %v", flaws)
	}
	if len(got) != 3 {
		t.Fatalf("1 single object + 2 JSON Lines = 3 expected: %d", len(got))
	}
	// `*.json` 묶음이 먼저, 그 다음이 `*.jsonl`. 회차끼리 비교하려면 순서가 정해져 있어야 한다.
	if got[0].GetEnvelope().GetTargetNodeId() != "n1" {
		t.Errorf("read order is off: %+v", got)
	}
}

// 빈 파일은 "결과 0건"이 아니라 **낸 쪽이 아무것도 못 냈다**는 신호다. 그대로 알린다.
func TestLoadDirReportsEmptyFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "node-b-jca.jsonl", "\n  \n")

	got, flaws := resultio.LoadDir(dir)
	if len(got) != 0 {
		t.Errorf("an empty file yielded results: %+v", got)
	}
	if len(flaws) != 1 || !errors.Is(flaws[0], resultio.ErrEmpty) {
		t.Fatalf("an empty file must be reported as a flaw: %v", flaws)
	}
	if flaws[0].Path == "" {
		t.Errorf("the flaw carries no file path: %v", flaws[0])
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
