package ingest

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/scope"
	"github.com/randyinthedev-hash/pqcota-common/pkg/kernel/sign"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
)

// IngestReport — 중앙 적재 결과 요약.
type IngestReport struct {
	Accepted  int // 수용된 CollectionResult 수
	OffScope  int // 미등재/앵커 없음 → 등재 판정 요청(§1.4)
	Rejected  int // 서명 검증 실패 → 거부(§2.6)
	Snapshots int // 적재된 노드 수(= 관측 기록 건수)
	Changed   int // 그중 실질 내용이 바뀌어 **새 스냅샷**이 생긴 노드 수
	// ExcludedByScope — 자산 스코프 정책으로 관리 대상에서 뺀 finding 수(제외 ≠ 부재 — 고지용).
	ExcludedByScope int
	// DeclaredAttributions — 이번에 받은 앱 선언 수. 관측이 아니므로 Accepted와 섞지 않는다.
	DeclaredAttributions int
	// Unverified — 서명을 **확인하지 못한** 건수. 검증 실패(Rejected)와 다르다 — 틀렸다는 것이
	// 아니라 물어보지 못했다는 것이다. 이 둘을 한 숫자로 합치면 "검증했고 통과했다"와
	// "검증할 키가 없었다"가 같은 모양이 된다(§2.6).
	Unverified int
	Nodes      []string           // 저장된 노드
	Notes      []string           // off-scope/거부 사유
	Conflicts  []IdentityConflict // node_id↔지문 중복/충돌(사용자 입력 검증, §1.4)
}

// RejectionStore — 받지 않은 사실을 남기는 곳. [history.Store]에 메서드를 더하지 않고 **별도
// 인터페이스**로 둔다(호환성 정책 §3②) — 밖의 구현체를 깨지 않고, PgStore·MemStore가 함께 만족한다.
type RejectionStore interface {
	AppendRejection(history.Rejection) error
}

// IngestOptions — 적재 한 번의 설정.
//
// 인자가 늘어날 때 시그니처를 바꾸는 대신 이 구조체를 받는다(호환성 정책 §3①). 기존
// [IngestResults]는 이것을 채워 [IngestWith]를 부르는 껍데기로 남는다.
type IngestOptions struct {
	Master         *scope.Master                            // nil이면 스코프 게이트 생략(로컬·데모)
	VerifySig      func(*discoveryv1.CollectionResult) bool // nil이면 검증하지 않는다
	SnapshotPrefix string
	RulesetVersion string
	Store          history.Store
	AssetPolicy    *scope.AssetPolicy // nil이면 관측된 자산 전부가 관리 대상

	// RequireSignature — 검증을 필수로 만든다. VerifySig가 nil이면 **적재 자체를 거절한다.**
	//
	// 기본이 아닌 이유: 전송 보안(mTLS·SSH)이 검증을 대신하는 경로가 실제로 있다. 그러나 그
	// 전제가 서지 않는 곳 — 여러 조직의 결과가 한 저장소로 모이는 곳 — 에서는 알리지 않고 통과하는
	// 경로가 열려 있으면 안 된다.
	RequireSignature bool

	// Rejections — 받지 않은 사실을 남길 곳. nil이면 [IngestReport]에만 남고 프로세스와 함께
	// 사라진다(v0.1.x와 같은 동작).
	Rejections RejectionStore
}

// ErrSignatureRequired — 필수 모드인데 검증자가 없다.
var ErrSignatureRequired = errors.New("signature verification is required but no public key is available")

// IngestResults — 회수된 CollectionResult[]를 중앙 인벤토리(히스토리)에 적재한다.
// 엣지↔중앙 경계를 넘어온 계약을 받아 노드별로 정규화·영속화하는 관문이다.
//
// 흐름(§1.4·§2.6·§2.4): 노드별 그룹핑 → 스코프 게이트 → 서명검증 → Normalize → history append.
//   - master=nil  : 스코프 게이트 생략(로컬/데모 — CMDB 없음).
//   - verifySig=nil: 서명검증 생략(전송 보안이 대신할 때, 예 mTLS/SSH).
//
// 미등재 노드는 저장하지 않고 등재 판정 요청으로 센다(§1.4 — 임의 수집 금지).
func IngestResults(
	results []*discoveryv1.CollectionResult,
	master *scope.Master,
	verifySig func(*discoveryv1.CollectionResult) bool,
	snapshotPrefix, rulesetVersion string,
	store history.Store,
	assetPolicy *scope.AssetPolicy, // nil이면 관측된 자산 전부가 관리 대상
) (*IngestReport, error) {
	return IngestWith(results, IngestOptions{
		Master: master, VerifySig: verifySig, SnapshotPrefix: snapshotPrefix,
		RulesetVersion: rulesetVersion, Store: store, AssetPolicy: assetPolicy,
	})
}

// IngestWith — [IngestResults]와 같은 일을 옵션 구조체로 받는다. 새 설정은 여기에만 붙는다.
func IngestWith(results []*discoveryv1.CollectionResult, o IngestOptions) (*IngestReport, error) {
	if o.RequireSignature && o.VerifySig == nil {
		return nil, ErrSignatureRequired
	}
	// 앱 선언은 **노드의 상태가 아니다** — 스냅샷 타임라인에 넣으면 조회·이력·diff가 저마다
	// 그것을 걸러 내야 하고, 화면이 늘 때마다 같은 자리가 다시 샌다. 여기서 갈라낸다.
	results, declared := splitAttributionDeclarations(results)
	master, verifySig, store := o.Master, o.VerifySig, o.Store
	snapshotPrefix, rulesetVersion, assetPolicy := o.SnapshotPrefix, o.RulesetVersion, o.AssetPolicy
	rep := &IngestReport{}
	if len(declared) > 0 {
		as, ok := o.Store.(history.AttributionStore)
		if !ok {
			return nil, errors.New("an app declaration arrived but the store cannot hold it")
		}
		for _, a := range declared {
			if err := as.PutAttribution(a); err != nil {
				return nil, err
			}
		}
		rep.DeclaredAttributions = len(declared)
	}
	rep.Conflicts = CheckIdentity(results) // 사용자 node_id 입력의 중복/충돌을 지문으로 교차검증(§1.4)
	for _, c := range rep.Conflicts {
		o.record(rep, nil, c.Key, history.RejectIdentity,
			c.Kind+": "+c.Key+" ↔ "+strings.Join(c.Members, ", "))
	}
	byNode := map[string][]*discoveryv1.CollectionResult{}
	var order []string

	for _, res := range results {
		node := res.GetEnvelope().GetTargetNodeId()
		if node == "" {
			rep.OffScope++
			rep.Notes = append(rep.Notes, "no target node given — no scope anchor")
			o.record(rep, res, "", history.RejectOffScope, "no target node given — no scope anchor")
			continue
		}
		if master != nil && !master.Registered(node) {
			rep.OffScope++
			rep.Notes = append(rep.Notes, node+": not registered → routed to a registration decision (§1.4)")
			o.record(rep, res, node, history.RejectOffScope, "not registered → routed to a registration decision (§1.4)")
			continue
		}
		if verifySig == nil {
			// 검증하지 않았다는 사실을 센다. 통과와 같은 자리에 두지 않는다.
			rep.Unverified++
			o.record(rep, res, node, history.RejectUnverified, "no public key to verify with — the signature was not checked")
		} else if !verifySig(res) {
			rep.Rejected++
			rep.Notes = append(rep.Notes, node+": signature verification failed → rejected (§2.6)")
			o.record(rep, res, node, history.RejectSignature, "signature verification failed (§2.6)")
			continue
		}
		if _, ok := byNode[node]; !ok {
			order = append(order, node)
		}
		byNode[node] = append(byNode[node], res)
		rep.Accepted++
	}

	// 노드별로 정규화 → append-only 히스토리 적재(§2.4⑥). 결정론: 같은 입력·규칙 → 같은 finding id.
	for _, node := range order {
		snapID := snapshotPrefix + ":" + node
		snap, err := normalize.Normalize(byNode[node], snapID, node, rulesetVersion, store, assetPolicy)
		if err != nil {
			return rep, err
		}
		rep.Snapshots++
		rep.ExcludedByScope += snap.ExcludedByScope
		if snap.Created { // 내용이 직전과 같으면 스냅샷은 새로 안 생기고 관측 기록만 남는다
			rep.Changed++
		}
		rep.Nodes = append(rep.Nodes, node)
	}
	return rep, nil
}

// splitAttributionDeclarations — 앱 선언을 관측 결과에서 갈라낸다.
//
// 판정은 내용으로 한다: 자산(CBOM)이 없고, 엣지가 전부 선언 표시를 달고 있으면 선언이다.
// 관측 결과는 어느 쪽이든 관측한 것을 담고 있으므로 여기 걸리지 않는다.
func splitAttributionDeclarations(in []*discoveryv1.CollectionResult) ([]*discoveryv1.CollectionResult, []history.EdgeAttribution) {
	var keep []*discoveryv1.CollectionResult
	var out []history.EdgeAttribution
	for _, r := range in {
		edges := r.GetObservedEdges()
		if len(r.GetCbomCyclonedx()) > 0 || len(edges) == 0 {
			keep = append(keep, r)
			continue
		}
		allDeclared := true
		for _, e := range edges {
			if e.GetAppKeyKind() != declaredKind || e.GetAppKey() == "" {
				allDeclared = false
				break
			}
		}
		if !allDeclared {
			keep = append(keep, r)
			continue
		}
		for _, e := range edges {
			out = append(out, history.EdgeAttribution{
				NodeID: e.GetSrcNodeId(), Dst: e.GetDstAddr(), AppKey: e.GetAppKey(),
			})
		}
	}
	return keep, out
}

// declaredKind — declaration.KindDeclared와 같은 값. 이 패키지가 declaration을 import하면
// 순환이 되므로 값을 둔다. 어긋나면 TestDeclaredKindMatches가 실패한다.
const declaredKind = "declared"

// record — 받지 않은 사실을 저장소에 남긴다. 남길 곳이 없으면 표시 없이 지나간다(v0.1.x와 같음).
//
// 남기다 실패해도 적재를 멈추지 않는다 — 기록을 못 남긴 것 때문에 관측까지 잃으면 손해가 크다.
// 대신 못 남겼다는 사실을 리포트에 적는다. 표시 없이 사라지게 두지 않는 것이 이 기록의 목적이다.
func (o IngestOptions) record(rep *IngestReport, res *discoveryv1.CollectionResult, node string, kind history.RejectionKind, reason string) {
	if o.Rejections == nil {
		return
	}
	r := history.Rejection{NodeID: node, Kind: kind, Reason: reason}
	if res != nil {
		r.CollectorID = res.GetEnvelope().GetCollectorId()
		r.CanonicalHash = fmt.Sprintf("%x", sha256.Sum256(sign.Canonical(res)))
	}
	if err := o.Rejections.AppendRejection(r); err != nil {
		rep.Notes = append(rep.Notes, "could not record the rejection: "+err.Error())
	}
}

// IngestCBOM — 외부 도구(CBOMkit/CipherIQ 등)가 낸 CycloneDX를 수신해 히스토리에 적재한다(SV-2·SD-7).
// ImportCBOM(서명검증→구조검증→스코프바인딩, 위임 수신 설계 §1)을 통과한 것만 CollectionResult로 감싸
// Normalize→store 한다. pqcota collector 경로(IngestResults)와 같은 뒷단을 공유 — 입력 형식만 다름.
func IngestCBOM(raw []byte, targetNodeID string, verifySig func([]byte) bool, snapshotPrefix, rulesetVersion string, store history.Store) (Disposition, error) {
	disp, env, _ := ImportCBOM(raw, targetNodeID, verifySig)
	if disp != Accepted {
		return disp, nil // Rejected(검증실패)·NeedsScopeBinding(앵커없음)은 저장하지 않는다.
	}
	res := &discoveryv1.CollectionResult{
		Envelope:             env, // ARTIFACT Envelope(SV-2)
		CbomCyclonedx:        raw,
		CyclonedxSpecVersion: "1.6",
		// 받은 바이트를 그대로 원본으로 남긴다 — 본문은 내부 정규 버전으로 수렴할 수 있어
		// 나중에 "무엇을 받았나"를 되짚으려면 수렴 전 바이트가 필요하다(§2.4 step 1).
		RawCapture: raw,
		RawFormat:  "external-cbom/cyclonedx",
	}
	snapID := snapshotPrefix + ":" + targetNodeID
	if _, err := normalize.Normalize([]*discoveryv1.CollectionResult{res}, snapID, targetNodeID, rulesetVersion, store, nil); err != nil {
		return disp, err
	}
	return Accepted, nil
}
