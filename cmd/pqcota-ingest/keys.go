// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/ingest"
)

// keyFileEnv — 노드에 묶은 키 파일의 경로.
const keyFileEnv = "PQCOTA_VERIFY_KEY_FILE"

// verifyKeys — 검증 키 설정을 읽은 것. bound·legacy·nodes 가운데 많아야 하나가 찬다(모두 비면 키 없음).
type verifyKeys struct {
	bound  map[string][]string // ID 결합 모드(PQCOTA_VERIFY_KEY의 <collector-id>:<key>)
	legacy []string            // 기존 목록 모드
	nodes  *sign.NodeKeys      // 노드 결합 모드(키 파일). 시작할 때 한 번 읽은 바이트를 파싱한 것을 실행 내내 쓴다
	file   string
}

// nodeCollectors — 노드에서 도는 수집기. 이 ID의 줄에 노드 `*`를 쓰면 그 수집기는 노드에 묶이지 않는다(경고).
var nodeCollectors = map[string]bool{
	"openssl-collector": true, "network-collector": true, "jvm-collector": true, "cng-collector": true,
}

// knownCollectors — 이 판의 수집기·선언 도구가 envelope에 적는 collector_id. 여기 없는 ID는 경고만 한다.
// 오타를 알리되 새 수집기를 막지 않는다.
var knownCollectors = map[string]bool{
	"openssl-collector": true, "network-collector": true, "jvm-collector": true,
	"cng-collector": true, "declaration-importer": true, "attribution-importer": true,
}

// loadVerifyKeys — 키 설정을 읽는다. 키 파일은 **여기서 한 번만 읽고** 그 바이트로 파싱한 것을 실행 내내 쓴다.
// 도중에 파일이 바뀌어도 이 실행의 판정은 바뀌지 않는다. 읽기·파싱 오류는 결과를 읽기 전에 돌려준다(종료 2).
func loadVerifyKeys() (verifyKeys, error) {
	env := os.Getenv("PQCOTA_VERIFY_KEY")
	if file := os.Getenv(keyFileEnv); file != "" {
		if strings.TrimSpace(env) != "" {
			return verifyKeys{}, fmt.Errorf("PQCOTA_VERIFY_KEY and %s are both set — use one. To check the key file while the ingest still uses PQCOTA_VERIFY_KEY, unset it for that one command: env -u PQCOTA_VERIFY_KEY %s=%s pqcota-ingest -verify-keys <results-dir>", keyFileEnv, keyFileEnv, file)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return verifyKeys{}, fmt.Errorf("%s: %w", keyFileEnv, err)
		}
		nk, err := sign.ParseNodeKeyFile(data)
		if err != nil {
			return verifyKeys{}, fmt.Errorf("%s (%s): %w", keyFileEnv, file, err)
		}
		return verifyKeys{nodes: nk, file: file}, nil
	}
	b, l, err := sign.ParseCollectorKeys(env)
	if err != nil {
		return verifyKeys{}, fmt.Errorf("PQCOTA_VERIFY_KEY: %w", err)
	}
	return verifyKeys{bound: b, legacy: l}, nil
}

// verifier — 결합 모드(수집기·노드)의 판정. 노드 결합은 노드에 묶인 키로 서명을 보고, 그다음 본문의 노드를 본다.
// 둘 다 아니면 nil.
func (k verifyKeys) verifier() func(*discoveryv1.CollectionResult) error {
	switch {
	case k.nodes != nil:
		return func(r *discoveryv1.CollectionResult) error {
			if err := sign.VerifyNodeBound(k.nodes, r); err != nil {
				return err
			}
			return ingest.CheckEdgeSources(r)
		}
	case k.bound != nil:
		return func(r *discoveryv1.CollectionResult) error { return sign.VerifyBound(k.bound, r) }
	}
	return nil
}

// fileStats — 키 파일의 노드 수(`*` 빼고), 서로 다른 키 수, `*` 줄 수.
func (k verifyKeys) fileStats() (nodes, keys, anyNode int) {
	ns, ks := map[string]bool{}, map[string]bool{}
	for _, e := range k.nodes.Entries() {
		ks[e.Key] = true
		if e.Node == sign.AnyNode {
			anyNode++
		} else {
			ns[e.Node] = true
		}
	}
	return len(ns), len(ks), anyNode
}

// scopeWarnings — 키 파일과 등록 파일(scope-master-file)이 어긋나는 노드. 두 게이트는 따로 돈다. 알리기만 한다.
func (k verifyKeys) scopeWarnings(registered []string) []string {
	if k.nodes == nil {
		return nil
	}
	reg := map[string]bool{}
	for _, id := range registered {
		reg[id] = true
	}
	inFile := map[string]bool{}
	for _, e := range k.nodes.Entries() {
		if e.Node != sign.AnyNode {
			inFile[e.Node] = true
		}
	}
	var out []string
	for _, n := range sortedKeys(inFile) {
		if !reg[n] {
			out = append(out, fmt.Sprintf("node %q has a key in the key file but is not in the registration list — its results are still refused by the scope gate", n))
		}
	}
	for _, n := range sortedKeys(reg) {
		if !inFile[n] {
			out = append(out, fmt.Sprintf("node %q is registered but has no key in the key file — its results will be refused", n))
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (k verifyKeys) count() int {
	n := 0
	for _, ks := range k.bound {
		n += len(ks)
	}
	return n
}

func (k verifyKeys) warnings() []string {
	var out []string
	if k.nodes != nil {
		return k.fileWarnings()
	}
	if len(k.legacy) > 0 {
		out = append(out, "the keys are not bound to collector IDs — any listed key passes for any collector. Write each as <collector-id>:<key> (see the migration steps in the docs).")
	}
	var ids []string
	for id := range k.bound {
		if !knownCollectors[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		out = append(out, fmt.Sprintf("collector ID %q is not one this version's collectors write — check for a typo", id))
	}
	return out
}

// fileWarnings — 키 파일의 경고(설정 오류가 아니다). 모르는 수집기 ID, 노드에서 도는 수집기의 `*`, 여러 노드에 적은 같은 키.
func (k verifyKeys) fileWarnings() []string {
	var out []string
	unknown := map[string]bool{}
	keyNodes := map[string]map[string]bool{}
	firstLine := map[string]int{}
	for _, e := range k.nodes.Entries() {
		for _, c := range e.Collectors {
			if !knownCollectors[c] {
				unknown[c] = true
			}
			if e.Node == sign.AnyNode && nodeCollectors[c] {
				out = append(out, fmt.Sprintf("line %d: %s is listed for every node (*) — a collector that runs on a node is then not bound to it", e.Line, c))
			}
		}
		if e.Node == sign.AnyNode {
			continue
		}
		if keyNodes[e.Key] == nil {
			keyNodes[e.Key] = map[string]bool{}
			firstLine[e.Key] = e.Line
		}
		keyNodes[e.Key][e.Node] = true
	}
	for _, c := range sortedKeys(unknown) {
		out = append(out, fmt.Sprintf("collector ID %q is not one this version's collectors write — check for a typo", c))
	}
	var shared []string
	for key, ns := range keyNodes {
		if len(ns) > 1 {
			shared = append(shared, fmt.Sprintf("key %s (first on line %d) is listed for %d nodes (%s) — those nodes are not told apart: a collector holding the key can sign as any of them",
				sign.Fingerprint(key), firstLine[key], len(ns), strings.Join(sortedKeys(ns), ", ")))
		}
	}
	sort.Strings(shared)
	return append(out, shared...)
}

// checkKeys — 전환 점검(-verify-keys). 저장하지 않는다. 결과마다 collector_id, 서명 여부, 맞은 키의 지문, 판정을
// 낸다. 지문은 **어느 키가 서명했는지**만 말한다. 그 ID와 키를 실제로 함께 배포했는지는 키 배포 기록과
// 대조해야 한다. 돌려주는 값은 종료 코드다(거부가 있으면 1).
func checkKeys(w io.Writer, results []*discoveryv1.CollectionResult, k verifyKeys) int {
	if k.bound == nil && len(k.legacy) == 0 && k.nodes == nil {
		fmt.Fprintf(os.Stderr, "-verify-keys: neither PQCOTA_VERIFY_KEY nor %s is set — there is no key to check against.\n", keyFileEnv)
		return 2
	}
	mode := "legacy key list (not bound to collector IDs)"
	switch {
	case k.nodes != nil:
		n, nk, anyN := k.fileStats()
		mode = fmt.Sprintf("bound to nodes by %s (%d nodes, %d keys, %d entries for any node)", k.file, n, nk, anyN)
	case k.bound != nil:
		mode = fmt.Sprintf("bound to collector IDs (%d IDs, %d keys)", len(k.bound), k.count())
	}
	verify := k.verifier()
	fmt.Fprintf(w, "key check — %s. Nothing is stored; the scope gate is not applied.\n\n", mode)
	fmt.Fprintf(w, "%-4s %-22s %-28s %-7s %-20s %s\n", "#", "collector_id", "target_node_id", "signed", "key", "verdict")
	accept, reject, unverified := 0, 0, 0
	for i, r := range results {
		env := r.GetEnvelope()
		signed := env.GetSignature() != ""
		fp, verdict := "-", ""
		if k.nodes != nil {
			// 맞은 줄 번호를 붙인다. 그 줄이 이 결과의 노드·수집기 줄이 아니면 어느 노드의 줄인지도 적는다.
			if e, ok := k.nodes.Match(r); ok {
				fp = fmt.Sprintf("%s L%d", sign.Fingerprint(e.Key), e.Line)
				if e.Node != env.GetTargetNodeId() && e.Node != sign.AnyNode {
					fp += " (" + e.Node + ")"
				}
			}
			if err := verify(r); err != nil {
				verdict = "reject: " + err.Error()
			}
		} else if k.bound != nil {
			if key, id, ok := matchAny(k.bound, r); ok {
				fp = sign.Fingerprint(key) + idNote(id, env.GetCollectorId())
			}
			if err := verify(r); err != nil {
				verdict = "reject: " + err.Error()
			}
		} else {
			if key, ok := sign.MatchingKey(k.legacy, r); ok {
				fp = sign.Fingerprint(key)
			}
			switch {
			case fp != "-":
			case !signed:
				verdict = "reject: " + sign.ErrNoSignature.Error()
			default:
				verdict = "reject: signature does not match any listed key"
			}
			if isAttributionDeclaration(r) {
				// 기존 목록 모드에서 앱 선언은 서명을 보지 않고 받는다(결합 모드로 바꾸면 이 줄이 판정 대상이 된다).
				verdict = "unverified (app declaration — the legacy mode does not check its signature)"
			}
		}
		switch {
		case verdict == "":
			verdict = "accept"
			accept++
		case verdict[0] == 'u':
			unverified++
		default:
			reject++
		}
		yn := "no"
		if signed {
			yn = "yes"
		}
		fmt.Fprintf(w, "%-4d %-22s %-28s %-7s %-20s %s\n", i+1, env.GetCollectorId(), env.GetTargetNodeId(), yn, fp, verdict)
	}
	fmt.Fprintf(w, "\n%d results: accept %d · reject %d · unverified %d\n", len(results), accept, reject, unverified)
	fmt.Fprintln(w, "The key column says which key signed a result (and, with a key file, on which line). Whether that key was really deployed with that collector ID and node is for")
	fmt.Fprintln(w, "you to check against your key distribution records. Do not drop a key only because it is missing here — a collector")
	fmt.Fprintln(w, "that did not run during the check would be cut off. Drop a key when no collector holds it in your records.")
	if reject > 0 {
		return 1
	}
	return 0
}

// matchAny — 결합 설정 전체에서 서명이 맞는 키와 그 키를 등록한 ID. 자기 ID를 먼저 본다.
func matchAny(bound map[string][]string, r *discoveryv1.CollectionResult) (key, id string, ok bool) {
	own := r.GetEnvelope().GetCollectorId()
	if key, ok := sign.MatchingKey(bound[own], r); ok {
		return key, own, true
	}
	ids := make([]string, 0, len(bound))
	for id := range bound {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if key, ok := sign.MatchingKey(bound[id], r); ok {
			return key, id, true
		}
	}
	return "", "", false
}

func idNote(matched, own string) string {
	if matched == own {
		return ""
	}
	return " (" + matched + ")"
}

// isAttributionDeclaration — 적재기가 앱 선언으로 갈라내는 결과인가(ingest의 판정과 같다: 자산이 없고 엣지가 모두
// 선언 표시를 단다). 점검 표가 기존 목록 모드의 실제 판정과 어긋나지 않게 하려고 둔다.
func isAttributionDeclaration(r *discoveryv1.CollectionResult) bool {
	edges := r.GetObservedEdges()
	if len(r.GetCbomCyclonedx()) > 0 || len(edges) == 0 {
		return false
	}
	for _, e := range edges {
		if e.GetAppKeyKind() != "declared" || e.GetAppKey() == "" {
			return false
		}
	}
	return true
}
