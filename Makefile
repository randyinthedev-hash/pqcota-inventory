# SPDX-FileCopyrightText: 2026 randyinthedev
# SPDX-License-Identifier: Apache-2.0
# pqcota-inventory — 인벤토리의 빌드·테스트
# 전제: go(go.mod의 toolchain 이상). 이 리포는 형제 모듈을 go.mod의 replace로 ../ 에서 읽는다(작업 공간 배치).

.PHONY: all fmt-check vet build test

all: fmt-check vet build test

# 전체 빌드 — Go(호스트 + **리눅스 타깃**) + Java 사이드카.
#
# ★ 리눅스 타깃을 따로 빌드하는 이유: collector의 핵심(`/proc`·AF_PACKET·attach)은 `//go:build linux`라
# **macOS에서는 컴파일 대상에서 빠진다.** 호스트 빌드만 하면 Mac 기여자가 그 코드를 깨도 통과한다.
# 교차 컴파일이 공짜(CGO_ENABLED=0)라 늘 함께 확인한다.
build:
	go build ./...
	@echo "→ 리눅스 타깃 교차 확인(리눅스 전용 파일 포함)"
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@# Windows 타깃도 함께 본다 — CNG collector가 여기서 자란다. 리눅스 전용 코드가
	@# 빌드 태그 밖으로 새면 **Windows에서만** 깨지므로, 그 코드를 쓰기 전에 게이트를 세운다.
	@CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... 2>&1 | head -20; \
	 CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o /dev/null ./... >/dev/null
	@echo "✓ Go 빌드(호스트 + linux/amd64 + windows/amd64) 통과"

# gofmt 게이트 — CONTRIBUTING이 gofmt를 규정하는데 검사가 없어 미포맷이 8건까지 쌓인 적이 있다.
# gen/(생성 코드)은 제외. 실패 시 어떤 파일인지 보여준다.
fmt-check:
	@files=$$(gofmt -l $$(git ls-files '*.go' | grep -v '^gen/') 2>/dev/null); \
	if [ -n "$$files" ]; then \
	  echo "✗ gofmt 필요:"; echo "$$files"; echo "  고치기: gofmt -w <파일>"; exit 1; \
	fi; \
	echo "✓ gofmt 통과"

vet:
	go vet ./...

test:
	go test ./...
