// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"sort"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
)

// verifyKeys — PQCOTA_VERIFY_KEY를 읽은 것. bound와 legacy 가운데 많아야 하나가 찬다(둘 다 비면 키 없음).
type verifyKeys struct {
	bound  map[string][]string // ID 결합 모드
	legacy []string            // 기존 목록 모드
}

// knownCollectors — 이 판의 수집기·선언 도구가 envelope에 적는 collector_id. 여기 없는 ID는 경고만 한다.
// 오타를 알리되 새 수집기를 막지 않는다.
var knownCollectors = map[string]bool{
	"openssl-collector": true, "network-collector": true, "jvm-collector": true,
	"cng-collector": true, "declaration-importer": true, "attribution-importer": true,
}

func loadVerifyKeys() (verifyKeys, error) {
	b, l, err := sign.ParseCollectorKeys(os.Getenv("PQCOTA_VERIFY_KEY"))
	return verifyKeys{bound: b, legacy: l}, err
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

// checkKeys — 전환 점검(-verify-keys). 저장하지 않는다. 결과마다 collector_id, 서명 여부, 맞은 키의 지문, 판정을
// 낸다. 지문은 **어느 키가 서명했는지**만 말한다. 그 ID와 키를 실제로 함께 배포했는지는 키 배포 기록과
// 대조해야 한다. 돌려주는 값은 종료 코드다(거부가 있으면 1).
func checkKeys(w io.Writer, results []*discoveryv1.CollectionResult, k verifyKeys) int {
	if k.bound == nil && len(k.legacy) == 0 {
		fmt.Fprintln(os.Stderr, "-verify-keys: PQCOTA_VERIFY_KEY is empty — there is no key to check against.")
		return 2
	}
	mode := "legacy key list (not bound to collector IDs)"
	if k.bound != nil {
		mode = fmt.Sprintf("bound to collector IDs (%d IDs, %d keys)", len(k.bound), k.count())
	}
	fmt.Fprintf(w, "key check — %s. Nothing is stored; the scope gate is not applied.\n\n", mode)
	fmt.Fprintf(w, "%-4s %-22s %-28s %-7s %-14s %s\n", "#", "collector_id", "target_node_id", "signed", "key", "verdict")
	accept, reject, unverified := 0, 0, 0
	for i, r := range results {
		env := r.GetEnvelope()
		signed := env.GetSignature() != ""
		fp, verdict := "-", ""
		if k.bound != nil {
			if key, id, ok := matchAny(k.bound, r); ok {
				fp = sign.Fingerprint(key) + idNote(id, env.GetCollectorId())
			}
			if err := sign.VerifyBound(k.bound, r); err != nil {
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
		fmt.Fprintf(w, "%-4d %-22s %-28s %-7s %-14s %s\n", i+1, env.GetCollectorId(), env.GetTargetNodeId(), yn, fp, verdict)
	}
	fmt.Fprintf(w, "\n%d results: accept %d · reject %d · unverified %d\n", len(results), accept, reject, unverified)
	fmt.Fprintln(w, "The key column says which key signed a result. Whether that key was really deployed with that collector ID is for")
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
