// SPDX-FileCopyrightText: 2026 randyinthedev
// SPDX-License-Identifier: Apache-2.0

// Command pqcota-profile — CMDB/사용자 프로필 CSV를 인벤토리 머신 프로필로 임포트한다(인벤토리 설계 §2.0).
// 식별(기계 관측)과 분리된 사람-대면 메타데이터(표시명·환경·역할·소유자·위치·labels) — UI 시각 구분용.
//
//	node_id,display_name,environment,role,owner,location,labels   (environment: production|staging|development|test)
//
// --dsn 지정 시 Postgres에 upsert(재사용·수정 가능), 미지정 시 파싱 결과만 출력.
//
// usage: pqcota-profile [--dsn <postgres>] <profiles.csv>
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/randyinthedev-hash/pqcota-common/pkg/org"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory"
)

// openMetaStore — 프로필을 쓸 메타 저장소. **PQCOTA_ORG를 읽는다.** 조직 없이 열면 기본 조직에 써서,
// 조직을 둔 배포에서 조회 쪽(`pqcota-inventory`)이 이 프로필을 못 본다. PQCOTA_REQUIRE_ORG=1이면
// 조직이 없을 때 열리지 않는다.
func openMetaStore(ctx context.Context, dsn string) (*inventory.PgMetaStore, error) {
	return inventory.NewPgMetaStoreIn(ctx, dsn, org.FromEnv())
}

func main() {
	dsn := flag.String("dsn", "", "inventory Postgres DSN; when given, upserts profiles")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-profile [--dsn <postgres>] <profiles.csv>")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	defer f.Close()

	profs, err := inventory.ParseProfiles(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse:", err)
		os.Exit(1)
	}

	fmt.Printf("%d profiles:\n", len(profs))
	for _, p := range profs {
		fmt.Printf("  %-14s %-16s %s · %s · owner=%s\n", p.GetNodeId(), p.GetDisplayName(),
			short(p.GetEnvironment().String(), "ENVIRONMENT_"), p.GetRole(), p.GetOwner())
	}

	if *dsn != "" {
		meta, err := openMetaStore(context.Background(), *dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "metadata store:", err)
			os.Exit(1)
		}
		defer meta.Close()
		for _, p := range profs {
			if err := meta.UpsertProfile(p); err != nil {
				fmt.Fprintln(os.Stderr, "upsert:", err)
				os.Exit(1)
			}
		}
		fmt.Fprintf(os.Stderr, "[profile] upserted %d profiles into the inventory (organization %s)\n", len(profs), meta.Org())
	}
}

func short(s, prefix string) string {
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}
