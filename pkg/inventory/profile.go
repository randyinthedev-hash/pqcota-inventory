package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	inventoryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/inventory/v1"
)

// ParseProfiles — 사용자/CMDB가 관리하는 CSV 프로필 파일을 MachineProfile로 읽는다(§2.0 선언·리뷰 레인).
// 헤더 필수(node_id 필수, 나머지 선택·순서 자유). 예:
//
//	node_id,display_name,environment,role,owner,location,labels
//
// environment: production|staging|development|test (대소문자 무관). labels: "k=v;k=v".
// 관측(식별)과 분리된 사람-대면 메타데이터라 임포트 출처는 CMDB로 태깅한다.
func ParseProfiles(r io.Reader) ([]*inventoryv1.MachineProfile, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 1 {
		return nil, fmt.Errorf("empty file")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.TrimSpace(strings.ToLower(h))] = i
	}
	if _, ok := col["node_id"]; !ok {
		return nil, fmt.Errorf("the header must contain node_id")
	}
	get := func(row []string, name string) string {
		if i, ok := col[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	var out []*inventoryv1.MachineProfile
	for _, row := range rows[1:] {
		if len(row) == 0 || strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		nid := get(row, "node_id")
		if nid == "" {
			continue
		}
		out = append(out, &inventoryv1.MachineProfile{
			NodeId:      nid,
			DisplayName: get(row, "display_name"),
			Environment: parseEnvironment(get(row, "environment")),
			Role:        get(row, "role"),
			Owner:       get(row, "owner"),
			Location:    get(row, "location"),
			Labels:      parseLabels(get(row, "labels")),
			Source:      inventoryv1.ProfileSource_PROFILE_SOURCE_CMDB, // CSV 임포트=선언
		})
	}
	return out, nil
}

func parseEnvironment(s string) inventoryv1.Environment {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "production", "prod":
		return inventoryv1.Environment_ENVIRONMENT_PRODUCTION
	case "staging", "stage":
		return inventoryv1.Environment_ENVIRONMENT_STAGING
	case "development", "dev":
		return inventoryv1.Environment_ENVIRONMENT_DEVELOPMENT
	case "test", "testing":
		return inventoryv1.Environment_ENVIRONMENT_TEST
	default:
		return inventoryv1.Environment_ENVIRONMENT_UNSPECIFIED
	}
}

// parseLabels — "k=v;k=v" → map. 빈 문자열이면 nil.
func parseLabels(s string) map[string]string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	m := map[string]string{}
	for _, pair := range strings.Split(s, ";") {
		if kv := strings.SplitN(strings.TrimSpace(pair), "=", 2); len(kv) == 2 {
			if k := strings.TrimSpace(kv[0]); k != "" {
				m[k] = strings.TrimSpace(kv[1])
			}
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
