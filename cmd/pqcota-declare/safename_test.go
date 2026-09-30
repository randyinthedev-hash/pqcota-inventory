package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// node_id는 `cmdb://web-1`처럼 스킴을 달고 다니는 것이 이 리포의 규약이다(데모·문서 전부
// 그 형식). 그런데 그 값을 그대로 파일명에 넣어 쓰기가 실패했다 — 없는 하위 디렉터리를
// 가리켰다. 문서가 쓰라는 형식으로 돌리면 깨지는 커맨드였다.
func TestSafeNameHandlesSchemeIDs(t *testing.T) {
	cases := map[string]string{
		"cmdb://web-1":     "cmdb-web-1",
		"host://local":     "host-local",
		"web-1":            "web-1",
		"cmdb://a//b":      "cmdb-a-b",
		"노드/1":             "1", // 비ASCII는 하이픈으로 바뀌고 앞뒤 하이픈은 잘린다 — 입력이 한국어인 것이 이 케이스의 요점이다
		"///":              "",
		"node_1.example":   "node_1.example",
		"UPPER/lower-MIX!": "UPPER-lower-MIX",
	}
	for in, want := range cases {
		got := safeName(in)
		if got != want {
			t.Errorf("safeName(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsRune(got, filepath.Separator) {
			t.Errorf("safeName(%q) = %q — a path separator survived", in, got)
		}
	}
}
