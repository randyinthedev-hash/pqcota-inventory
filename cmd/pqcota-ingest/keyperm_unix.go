// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// keyFilePermWarnings — 이 실행의 사용자가 키 파일이나 그 디렉터리에 쓸 수 있으면 알린다. 설정 오류가 아니다(막지 않는다).
// 키 파일은 운영자가 관리하고 적재 계정은 읽기만 해야 한다. 파일을 쓴다는 것만으로 적재 계정의 변경이 막히지 않는다:
// 적재 계정이 쓸 수 있으면 어느 키를 믿을지도 바꿀 수 있다. 판정은 이미 읽은 바이트로 하므로, 여기서 경로를 다시
// 보는 것은 알리기 위해서일 뿐이다.
func keyFilePermWarnings(path string) []string {
	const wOK = 2 // access(2)의 W_OK
	var out []string
	if syscall.Access(path, wOK) == nil {
		out = append(out, "this account can write the key file — whoever runs the ingest could change which keys are trusted. Make it owned by the operator and only readable by this account")
	}
	if dir := filepath.Dir(path); syscall.Access(dir, wOK) == nil {
		out = append(out, fmt.Sprintf("this account can write the directory %s — it could replace the key file", dir))
	}
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o022 != 0 {
		out = append(out, fmt.Sprintf("the key file is writable by its group or by others (mode %04o)", fi.Mode().Perm()))
	}
	return out
}
