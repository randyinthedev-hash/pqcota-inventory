// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"google.golang.org/protobuf/encoding/protojson"
)

// 시험 실행 파일이 자기 자신을 이 명령으로 다시 띄운다. 종료 코드와 출력을 그대로 잰다.
func TestMain(m *testing.M) {
	if os.Getenv("PQCOTA_INGEST_TEST_MAIN") == "1" {
		os.Args = append([]string{"pqcota-ingest"}, strings.Fields(os.Getenv("PQCOTA_INGEST_TEST_ARGS"))...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runIngest(t *testing.T, verifyKey string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"PQCOTA_INGEST_TEST_MAIN=1",
		"PQCOTA_INGEST_TEST_ARGS="+strings.Join(args, " "),
		"PQCOTA_VERIFY_KEY="+verifyKey,
		"PQCOTA_REQUIRE_SIGNATURE=",
		"PQCOTA_DSN=",
	)
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), o.String(), e.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, o.String(), e.String()
}

func writeResult(t *testing.T, dir, name, id, priv string) {
	t.Helper()
	r := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{CollectorId: id, TargetNodeId: "web-01"}, RawFormat: "test/v1"}
	if priv != "" {
		if err := sign.SignAll(priv, []*discoveryv1.CollectionResult{r}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := protojson.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// 키 설정이 틀리면 결과를 읽기 전에 종료 코드 2로 멈추고, 메시지에 키 값이 나오지 않는다. 결과 폴더가 없어도
// 2다(폴더를 먼저 읽었다면 「결과 없음」으로 1이 났을 것이다).
func TestBadKeyConfigStopsBeforeReadingResults(t *testing.T) {
	k, _, _ := sign.Generate()
	k2, _, _ := sign.Generate()
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	for name, v := range map[string]string{
		"mixed":     "openssl-collector:" + k + "," + k2,
		"empty id":  ":" + k,
		"empty key": "openssl-collector:",
		"base64":    "openssl-collector:not*base64",
		"length":    "openssl-collector:" + k[:20],
		"duplicate": "openssl-collector:" + k + ",openssl-collector:" + k,
	} {
		code, out, errOut := runIngest(t, v, missing)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s%s", name, code, out, errOut)
		}
		if strings.Contains(out+errOut, k) || strings.Contains(out+errOut, k2) || strings.Contains(out+errOut, k[:20]) {
			t.Errorf("%s: the key is printed:\n%s", name, errOut)
		}
		if strings.Contains(errOut, "no result found") {
			t.Errorf("%s: it read the results first", name)
		}
	}
}

// -verify-keys는 저장하지 않고 결과마다 ID·서명 여부·키 지문·판정을 낸다. 거부가 있으면 1.
func TestVerifyKeysReport(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	dir := t.TempDir()
	writeResult(t, dir, "a.json", "openssl-collector", kPriv)
	writeResult(t, dir, "b.json", "network-collector", kPriv)
	writeResult(t, dir, "c.json", "openssl-collector", "")

	// 기존 목록: 지문은 어느 키가 서명했는지만 말한다. 다른 ID도 통과한다.
	code, out, errOut := runIngest(t, k, "-verify-keys", dir)
	fp := sign.Fingerprint(k)
	if code != 1 || strings.Count(out, fp) != 2 || !strings.Contains(out, "accept 2 · reject 1") ||
		!strings.Contains(errOut, "not bound to collector IDs") || !strings.Contains(out, "key distribution records") {
		t.Errorf("legacy: exit %d\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, k) {
		t.Error("the key itself is printed")
	}

	// 결합: 같은 키라도 등록되지 않은 ID는 거부한다.
	code, out, _ = runIngest(t, "openssl-collector:"+k, "-verify-keys", dir)
	if code != 1 || !strings.Contains(out, "accept 1 · reject 2") ||
		!strings.Contains(out, "bound to collector IDs (1 IDs, 1 keys)") ||
		!strings.Contains(out, fp+" (openssl-collector)") || !strings.Contains(out, "reject: no signature") {
		t.Errorf("bound: exit %d\n%s", code, out)
	}

	// 모두 맞으면 0.
	ok := t.TempDir()
	writeResult(t, ok, "a.json", "openssl-collector", kPriv)
	if code, out, _ := runIngest(t, "openssl-collector:"+k, "-verify-keys", ok); code != 0 || !strings.Contains(out, "accept 1 · reject 0") {
		t.Errorf("all accepted: exit %d\n%s", code, out)
	}
}

// 결합 모드의 실제 적재: 자기 ID는 들어가고, 다른 ID·서명 없음은 거부된다. 요약 줄이 모드를 말한다.
func TestBoundIngestSummary(t *testing.T) {
	k, kPriv, _ := sign.Generate()
	dir := t.TempDir()
	writeResult(t, dir, "a.json", "openssl-collector", kPriv)
	writeResult(t, dir, "b.json", "network-collector", kPriv)
	writeResult(t, dir, "c.json", "openssl-collector", "")
	code, out, errOut := runIngest(t, "openssl-collector:"+k, dir)
	if code != 0 || !strings.Contains(out, "bound to collector IDs (1 IDs, 1 keys)") ||
		!strings.Contains(out, "accepted 1 · unregistered/no-anchor 0 · signature-rejected 2") ||
		strings.Contains(out, "unverified signatures") {
		t.Errorf("exit %d\n%s%s", code, out, errOut)
	}
}

// runIngestEnv — 환경 변수를 직접 준다(키 파일 모드). PQCOTA_VERIFY_KEY는 비운다.
func runIngestEnv(t *testing.T, env []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"PQCOTA_INGEST_TEST_MAIN=1",
		"PQCOTA_INGEST_TEST_ARGS="+strings.Join(args, " "),
		"PQCOTA_VERIFY_KEY=", "PQCOTA_VERIFY_KEY_FILE=", "PQCOTA_REQUIRE_SIGNATURE=", "PQCOTA_DSN=",
	)
	cmd.Env = append(cmd.Env, env...)
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), o.String(), e.String()
	} else if err != nil {
		t.Fatal(err)
	}
	return 0, o.String(), e.String()
}

func writeNodeResult(t *testing.T, dir, name, id, node, priv string) {
	t.Helper()
	r := &discoveryv1.CollectionResult{Envelope: &commonv1.Envelope{CollectorId: id, TargetNodeId: node}, RawFormat: "test/v1"}
	if priv != "" {
		if err := sign.SignAll(priv, []*discoveryv1.CollectionResult{r}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := protojson.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeKeyFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "verify-keys")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// N6 — 키 파일의 설정 오류는 결과를 읽기 전에 종료 2이고 키 값을 내지 않는다. 두 변수를 함께 쓰는 것도 2다.
// self-id(node:…)는 받는다.
func TestKeyFileConfigErrorsStopBeforeReadingResults(t *testing.T) {
	k, _, _ := sign.Generate()
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	cases := map[string][]string{
		"fields":       {"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "web-01 "+k+"\n", 0o644)},
		"host://local": {"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "host://local openssl-collector "+k+"\n", 0o644)},
		"length":       {"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "web-01 openssl-collector "+k[:20]+"\n", 0o644)},
		"duplicate":    {"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "web-01 openssl-collector "+k+"\nweb-01 openssl-collector "+k+"\n", 0o644)},
		"no file":      {"PQCOTA_VERIFY_KEY_FILE=" + filepath.Join(t.TempDir(), "absent")},
		"both set":     {"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "web-01 openssl-collector "+k+"\n", 0o644), "PQCOTA_VERIFY_KEY=openssl-collector:" + k},
	}
	for name, env := range cases {
		code, out, errOut := runIngestEnv(t, env, missing)
		if code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s%s", name, code, out, errOut)
		}
		if strings.Contains(out+errOut, k[:20]) {
			t.Errorf("%s: the key is printed:\n%s", name, errOut)
		}
		if strings.Contains(errOut, "no result found") {
			t.Errorf("%s: it read the results first", name)
		}
	}
	if _, _, errOut := runIngestEnv(t, cases["both set"], missing); !strings.Contains(errOut, "env -u PQCOTA_VERIFY_KEY") {
		t.Errorf("both set: the message does not show how to check the file: %s", errOut)
	}
	ok := t.TempDir()
	code, out, errOut := runIngestEnv(t, []string{"PQCOTA_VERIFY_KEY_FILE=" + writeKeyFile(t, "node:3f9a1c openssl-collector "+k+"\n", 0o644)}, ok)
	if code == 2 {
		t.Errorf("a self-id node was refused: %s%s", out, errOut)
	}
}

// N7·N14 — -verify-keys는 저장하지 않고 노드·맞은 줄·지문·판정을 낸다. 쓰기 권한 경고는 설정 오류와 따로 나오고
// 종료 코드를 바꾸지 않는다.
func TestKeyFileVerifyKeysAndPermissionWarning(t *testing.T) {
	k1, p1, _ := sign.Generate()
	k2, _, _ := sign.Generate()
	dir := t.TempDir()
	writeNodeResult(t, dir, "a.json", "openssl-collector", "web-01", p1)
	writeNodeResult(t, dir, "b.json", "openssl-collector", "web-02", p1)
	file := writeKeyFile(t, "# test\nweb-01 openssl-collector "+k1+"\nweb-02 openssl-collector "+k2+"\n", 0o644)
	code, out, errOut := runIngestEnv(t, []string{"PQCOTA_VERIFY_KEY_FILE=" + file}, "-verify-keys", dir)
	fp := sign.Fingerprint(k1)
	if code != 1 || !strings.Contains(out, "bound to nodes by "+file+" (2 nodes, 2 keys, 0 entries for any node)") ||
		!strings.Contains(out, fp+" L2") || !strings.Contains(out, fp+" L2 (web-01)") ||
		!strings.Contains(out, "does not match the keys registered for openssl-collector on web-02") ||
		!strings.Contains(out, "accept 1 · reject 1") {
		t.Errorf("exit %d\n%s%s", code, out, errOut)
	}
	if strings.Contains(out, k1) {
		t.Error("the key itself is printed")
	}
	// 시험을 도는 사용자는 자기 임시 파일에 쓸 수 있다 — 경고가 나와야 한다. 설정 오류(종료 2)가 아니다.
	if !strings.Contains(errOut, "PQCOTA_VERIFY_KEY_FILE permissions: this account can write the key file") {
		t.Errorf("no permission warning: %s", errOut)
	}
	g := writeKeyFile(t, "web-01 openssl-collector "+k1+"\n", 0o666)
	if _, _, errOut := runIngestEnv(t, []string{"PQCOTA_VERIFY_KEY_FILE=" + g}, "-verify-keys", dir); !strings.Contains(errOut, "writable by its group or by others") {
		t.Errorf("group/other write: %s", errOut)
	}
}

// 키 파일 모드의 실제 적재와 경고: 요약 줄, 등록 파일과의 어긋남, 공유 키, 노드 수집기의 `*`.
func TestKeyFileIngestSummaryAndWarnings(t *testing.T) {
	k1, p1, _ := sign.Generate()
	ks, _, _ := sign.Generate()
	dir := t.TempDir()
	writeNodeResult(t, dir, "a.json", "openssl-collector", "web-01", p1)
	writeNodeResult(t, dir, "b.json", "openssl-collector", "web-02", p1)
	file := writeKeyFile(t, "web-01 openssl-collector "+k1+"\nweb-03 openssl-collector "+ks+"\nweb-04 openssl-collector "+ks+"\n* jvm-collector "+ks+"\n", 0o644)
	scopeFile := filepath.Join(t.TempDir(), "scope")
	if err := os.WriteFile(scopeFile, []byte("web-01\nweb-02\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runIngestEnv(t, []string{"PQCOTA_VERIFY_KEY_FILE=" + file}, dir, scopeFile)
	if code != 0 || !strings.Contains(out, "bound to nodes (3 nodes, 2 keys, 1 entries for any node)") ||
		!strings.Contains(out, "accepted 1 · unregistered/no-anchor 0 · signature-rejected 1") {
		t.Errorf("summary: exit %d\n%s%s", code, out, errOut)
	}
	for _, w := range []string{
		`node "web-03" has a key in the key file but is not in the registration list`,
		`node "web-02" is registered but has no key in the key file`,
		"is listed for 2 nodes (web-03, web-04)",
		"line 4: jvm-collector is listed for every node (*)",
	} {
		if !strings.Contains(errOut, w) {
			t.Errorf("warning missing: %q\n%s", w, errOut)
		}
	}
}
