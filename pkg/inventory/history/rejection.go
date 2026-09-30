package history

import (
	"context"
	"sync"
	"time"
)

// RejectionKind — 적재가 결과를 받지 않은 이유의 갈래.
type RejectionKind string

const (
	// RejectSignature — 서명 검증 실패(§2.6).
	RejectSignature RejectionKind = "signature"
	// RejectUnverified — 검증할 키가 없어 서명을 **확인하지 못했다.** 실패와 다르다 —
	// 틀렸다는 것이 아니라 물어보지 못했다는 것이다.
	RejectUnverified RejectionKind = "unverified"
	// RejectOffScope — 미등재 노드이거나 스코프 앵커가 없다(§1.4).
	RejectOffScope RejectionKind = "off-scope"
	// RejectIdentity — node_id ↔ 머신 지문의 중복·충돌(§1.4).
	RejectIdentity RejectionKind = "identity"
)

// Rejection — 받지 않은 사실의 기록.
//
// **왜 남기나** — `IngestReport`는 반환값이라 화면에 찍히고 사라진다. 그러면 나중에 "러너가
// 잘못 설정돼 계속 거절당하고 있었다"와 "그 노드에서는 아무 일도 없었다"가 구분되지 않는다.
// 절단 기록([RetentionEvent])이 이력의 구멍을 "관측 안 함"과 구분해 주는 것과 같은 자리, 같은 이유다.
//
// 원문은 담지 않는다. 거절된 결과를 그대로 보관하면 검증하지 않은 데이터를 저장소가 쥐게 된다 —
// 대신 canonical 지문만 남겨, 같은 것이 반복해 오는지를 셀 수 있게 한다.
type Rejection struct {
	Seq           int64
	NodeID        string // 알아낼 수 있었으면. 앵커가 없으면 빈 값
	CollectorID   string
	Kind          RejectionKind
	Reason        string
	CanonicalHash string // sign.Canonical의 지문. 원문 대신 남긴다
	At            time.Time
}

// rejectionSchemaSQL — 거절 이력. 스냅샷과 달리 조회 축이 시간이라 인덱스도 그렇게 둔다.
const rejectionSchemaSQL = `
CREATE TABLE IF NOT EXISTS pqcota_rejections (
    seq            BIGSERIAL PRIMARY KEY,
    org            TEXT NOT NULL DEFAULT 'default',
    node_id        TEXT NOT NULL DEFAULT '',
    collector_id   TEXT NOT NULL DEFAULT '',
    kind           TEXT NOT NULL,
    reason         TEXT NOT NULL,
    canonical_hash TEXT NOT NULL DEFAULT '',
    at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_pqcota_rej_org ON pqcota_rejections(org, at DESC);
`

// AppendRejection — 받지 않은 사실을 남긴다. 조직은 핸들에서 온다.
func (p *PgStore) AppendRejection(r Rejection) error {
	_, err := p.pool.Exec(context.Background(),
		`INSERT INTO pqcota_rejections(org,node_id,collector_id,kind,reason,canonical_hash)
		 VALUES($1,$2,$3,$4,$5,$6)`,
		p.org, r.NodeID, r.CollectorID, string(r.Kind), r.Reason, r.CanonicalHash)
	return err
}

// Rejections — 이 조직에 남은 거절 기록(최근 것부터). limit<=0이면 100건.
func (p *PgStore) Rejections(limit int) ([]Rejection, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.pool.Query(context.Background(),
		`SELECT seq,node_id,collector_id,kind,reason,canonical_hash,at FROM pqcota_rejections
		 WHERE org=$1 ORDER BY seq DESC LIMIT $2`, p.org, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rejection
	for rows.Next() {
		var r Rejection
		var kind string
		if err := rows.Scan(&r.Seq, &r.NodeID, &r.CollectorID, &kind, &r.Reason, &r.CanonicalHash, &r.At); err != nil {
			return nil, err
		}
		r.Kind = RejectionKind(kind)
		out = append(out, r)
	}
	return out, rows.Err()
}

// memRejections — MemStore의 거절 기록. 프로세스와 함께 사라진다(영속은 PgStore).
type memRejections struct {
	mu   sync.Mutex
	list []Rejection
}

// AppendRejection — MemStore도 같은 규칙을 만족한다. Pg판만 남기면 테스트가 기록 없는 경로를 탄다.
func (m *MemStore) AppendRejection(r Rejection) error {
	m.rej.mu.Lock()
	defer m.rej.mu.Unlock()
	r.Seq = int64(len(m.rej.list)) + 1
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	m.rej.list = append(m.rej.list, r)
	return nil
}

// Rejections — 최근 것부터. limit<=0이면 전부.
func (m *MemStore) Rejections(limit int) ([]Rejection, error) {
	m.rej.mu.Lock()
	defer m.rej.mu.Unlock()
	out := make([]Rejection, 0, len(m.rej.list))
	for i := len(m.rej.list) - 1; i >= 0; i-- {
		if limit > 0 && len(out) == limit {
			break
		}
		out = append(out, m.rej.list[i])
	}
	return out, nil
}
