// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

// Package sourceevidence — 외부 CycloneDX CBOM이 보고한 암호 정보와 소스 위치를 「소스 근거」로 바꾼다.
//
// 런타임 관측(스냅샷)과는 따로 둔다. 스냅샷의 finding을 만들지 않고, 노드의 최신 상태를 바꾸지 않는다.
// 이 패키지는 변환만 한다(저장·화면은 다른 곳). 변환 결과는 불변이다 — 같은 입력·규칙·변환기 판이면
// 같은 결과가 나오고, 저장한 결과를 나중에 다른 규칙으로 다시 읽지 않는다.
//
// 원칙 둘(설계 v2.1 §5.1):
//   - 입력이 주지 않은 것을 만들지 않는다. 여러 호출을 한 컴포넌트로 합친 입력에서 위치마다의 호출 종류를
//     되살리지 않고, 컴포넌트 단위 값을 위치에 나눠 붙이지 않는다.
//   - 위치는 「보고된 검토 위치」다. 호출·선언·주석 같은 종류는 입력이 구분해 줄 때만 적는다.
package sourceevidence

// 판 — 저장 형식·변환기·표준 규칙은 각자 판을 가진다. 뜻이 바뀌면 판을 올리고, 같은 판의 동작을 바꾸지 않는다.
const (
	SchemaVersion    = "1"
	ConverterVersion = "sourceevidence/1"

	// StandardRuleID·StandardRuleRevision — CycloneDX 표준 `evidence.occurrences`를 읽는 규칙.
	StandardRuleID       = "standard-occurrences"
	StandardRuleRevision = "1"
)

// Base — 줄·열의 시작 기준. 모르면 Unknown이고, 그때는 정규화한 값을 만들지 않는다.
type Base string

const (
	Base0       Base = "0"
	Base1       Base = "1"
	BaseUnknown Base = "unknown"
)

// LocationKindNotSupplied — 위치가 호출·선언·헤더·주석 중 무엇인지 입력이 말하지 않았다.
// 첫 판에는 이것을 채우는 규칙이 없으므로 모든 위치가 이 값이다.
const LocationKindNotSupplied = "not_supplied"

// RuleRef — 위치를 만든 규칙. 출처(standard·preset·user)·ID·판·내용 해시가 모두 같아야 같은 규칙이다.
type RuleRef struct {
	Source   string `json:"source"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
	SHA256   string `json:"sha256"`
}

// String — 화면용 `id@revision`.
func (r RuleRef) String() string { return r.ID + "@" + r.Revision }

// Interpretation — 입력 하나를 정해진 규칙으로 읽은 결과(불변).
type Interpretation struct {
	ID               string       `json:"id"`
	SchemaVersion    string       `json:"schemaVersion"`
	ConverterVersion string       `json:"converterVersion"`
	InputSHA256      string       `json:"inputSha256"`
	SpecVersion      string       `json:"specVersion"` // 본문이 선언한 판 그대로
	Rules            []RuleRef    `json:"rules"`
	ExcludedRuleIDs  []string     `json:"excludedRuleIds"`
	Producer         []Field      `json:"producer"` // metadata.tools가 보고한 도구(이름·판·만든 곳)
	Counts           Counts       `json:"counts"`
	Items            []Item       `json:"items"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
}

// Counts — 미리보기·조회의 요약 숫자. 「위치 없음」은 오류가 아니라 정상 입력이다.
type Counts struct {
	Components        int            `json:"components"`        // 대상(cryptographic-asset) 컴포넌트
	OutOfScope        int            `json:"outOfScope"`        // 그 밖의 컴포넌트(세기만 한다)
	ItemsWithLocation int            `json:"itemsWithLocation"` // 위치가 하나라도 있는 항목
	Locations         int            `json:"locations"`
	Diagnostics       map[string]int `json:"diagnostics"` // 진단 코드별 수(항목·위치 진단 포함)
}

// Item — 대상 컴포넌트 하나.
type Item struct {
	ID               string       `json:"id"`
	ComponentPointer string       `json:"componentPointer"`
	Reported         []Field      `json:"reported"` // 표준 필드의 보고값. 값마다 원본 포인터가 있다
	External         []Field      `json:"external"` // 해석하지 않은 properties. 도구의 평가도 여기 — pqcota 판정이 아니다
	Locations        []Location   `json:"locations"`
	Diagnostics      []Diagnostic `json:"diagnostics"`
}

// Field — 보고값 하나와 그 값이 있던 자리.
type Field struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Pointer string `json:"pointer"`
}

// Location — 원본 위치 하나. 같은 값이 여럿이어도 합치지 않는다(원본 포인터마다 하나).
type Location struct {
	ID             string            `json:"id"`
	Rule           RuleRef           `json:"rule"`
	SourcePointers map[string]string `json:"sourcePointers"` // 예: {"occurrence": "/components/0/evidence/occurrences/2"}
	Reported       ReportedLocation  `json:"reported"`
	LineBase       Base              `json:"lineBase"`
	ColumnBase     Base              `json:"columnBase,omitempty"`
	ColumnUnit     string            `json:"columnUnit,omitempty"`
	Normalized     Normalized        `json:"normalized"`
	Kind           string            `json:"kind"`
	Diagnostics    []Diagnostic      `json:"diagnostics"`
}

// ReportedLocation — 읽은 그대로. 없는 값은 nil(0으로 채우지 않는다).
type ReportedLocation struct {
	Raw     string `json:"raw,omitempty"` // 결합 문자열이면 원문
	Path    string `json:"path"`
	Line    *int64 `json:"line,omitempty"`
	Column  *int64 `json:"column,omitempty"`
	Offset  *int64 `json:"offset,omitempty"` // 단위·기준이 정해지지 않아 보존만 한다
	Symbol  string `json:"symbol,omitempty"`
	Context string `json:"context,omitempty"`
}

// Normalized — 1부터 세는 내부 좌표. 기준을 모르는 값은 비우고 이유를 적는다.
// 경로는 첫 판에서 바꾸지 않는다(대소문자·구분자 정규화 없음).
type Normalized struct {
	Path         string `json:"path"`
	Line         *int64 `json:"line,omitempty"`
	Column       *int64 `json:"column,omitempty"`
	AbsentReason string `json:"absentReason,omitempty"`
}

// Diagnostic — 변환이 알린 사실. Pointer는 원본 안의 자리.
type Diagnostic struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// 진단 코드.
const (
	DiagLocationMissing   = "location-missing"  // occurrence에 location 문자열이 없다 → 위치를 만들지 않는다
	DiagInvalidLine       = "invalid-line"      // line이 0 이상의 정수가 아니다
	DiagInvalidOffset     = "invalid-offset"    // offset이 0 이상의 정수가 아니다
	DiagLineBaseUnknown   = "line-base-unknown" // 줄의 시작 기준을 몰라 정규화하지 않았다
	DiagPrimitiveNotInVer = "primitive-not-in-spec"
	DiagDeprecatedField   = "deprecated-field"
	DiagWrongType         = "wrong-type" // 해석 대상 필드가 있는데 자료형이 틀리다(없는 것과 구분한다)
)
