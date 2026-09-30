package inventory

import (
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
)

// AttributionOverlay — 선언된 엣지의 앱을 조회 시점에 얹기 위한 색인.
//
// **저장을 고치지 않는다.** 선언은 자기 레인에 그대로 있고, 관측 엣지도 그대로다. 둘을 합치는
// 일은 여기서, **읽을 때만** 일어난다 — 적재가 관측을 고치면 collector의 서명과 어긋나고,
// `raw_capture`에서 다시 계산할 때 저장된 값과 달라진다(검토 중인 설계 §7.5).
type AttributionOverlay struct {
	byEdge map[edgeKey]string
}

// edgeKey — (관측 호스트, 상대 주소). 상대 주소가 이미 포트를 담으므로 포트를 따로 두지 않는다.
type edgeKey struct{ node, dst string }

// BuildAttributionOverlay — 선언 저장소에서 색인을 만든다.
//
// **스냅샷을 읽지 않는다.** 선언은 노드의 상태 이력 밖에 산다 — 거기 넣으면 조회·이력·diff가
// 저마다 그것을 걸러 내야 하고, 화면이 늘 때마다 같은 자리가 다시 샌다.
func BuildAttributionOverlay(store history.AttributionStore) *AttributionOverlay {
	o := &AttributionOverlay{byEdge: map[edgeKey]string{}}
	if store == nil {
		return o
	}
	as, err := store.Attributions()
	if err != nil {
		return o // 선언은 덤이다 — 못 읽어도 관측을 보여 주는 본업은 멈추지 않는다
	}
	for _, a := range as {
		o.byEdge[edgeKey{a.NodeID, a.Dst}] = a.AppKey
	}
	return o
}

// Apply — 엣지 하나에 선언을 얹는다. 관측이 이미 채운 자리는 **손대지 않는다.**
//
// 덮어쓰게 두면 사람이 적은 것과 기계가 본 것이 섞이고, 선언 레인을 따로 둔 이유가 사라진다.
// 원본 엣지도 고치지 않는다 — 화면에 낼 값만 돌려준다.
func (o *AttributionOverlay) Apply(e *discoveryv1.ObservedEdge) (key, kind string) {
	if e.GetAppKey() != "" {
		return e.GetAppKey(), e.GetAppKeyKind() // 관측이 우선한다
	}
	if o == nil {
		return "", ""
	}
	if k, ok := o.byEdge[edgeKey{e.GetSrcNodeId(), edgeDstKey(e)}]; ok {
		return k, declaration.KindDeclared
	}
	return "", ""
}

// Len — 색인에 든 선언 수.
func (o *AttributionOverlay) Len() int {
	if o == nil {
		return 0
	}
	return len(o.byEdge)
}

// edgeDstKey — 선언이 가리키는 상대. 주소가 있으면 그것을, 노드로 이어져 주소가 비면 노드 ID를
// 쓴다 — 화면에 보이는 값과 같아야 사람이 그대로 옮겨 적을 수 있다.
func edgeDstKey(e *discoveryv1.ObservedEdge) string {
	if a := e.GetDstAddr(); a != "" {
		return a
	}
	return e.GetDstNodeId()
}
