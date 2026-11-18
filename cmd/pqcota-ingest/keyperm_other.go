// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package main

// keyFilePermWarnings — 쓰기 권한을 재는 방법이 이 OS에서는 다르다. 알리지 않는다.
func keyFilePermWarnings(path string) []string { return nil }
