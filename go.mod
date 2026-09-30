module github.com/randyinthedev-hash/pqcota-inventory

go 1.26.4

require github.com/randyinthedev-hash/pqcota-common v0.10.0

require (
	github.com/jackc/pgx/v5 v5.10.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
	google.golang.org/grpc v1.82.1 // indirect
)

// 로컬 작업 공간에서만 쓰는 연결이다. 모듈에 태그가 붙으면 이 replace를 지우고 require를 그 태그로 올린다.
replace github.com/randyinthedev-hash/pqcota-common => ../pqcota-common
