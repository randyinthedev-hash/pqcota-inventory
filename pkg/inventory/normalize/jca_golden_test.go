// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package normalize_test

import (
	"testing"
	"time"

	commonv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/common/v1"
	discoveryv1 "github.com/randyinthedev-hash/pqcota-common/gen/pqcota/discovery/v1"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/history"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/normalize"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// v0.11.0 골든 — **app_key_kind가 없는 옛 입력은 v0.12.0에서도 finding id와 지문이 같다.**
//
// 값은 v0.11.0(inventory 3a314c9)의 코드로 이 입력을 정규화해 얻은 것이다. JCA 식별 1단계는 kind가 있는
// 새 입력에만 새 id 형식과 새 지문 줄을 쓴다. 옛 입력이 이 값에서 벗어나면 저장된 이력·계획 참조가
// 같은 규칙으로 다시 찾히지 않는다. 규칙 판 문자열은 지문에 들어가므로 v0.11.0의 값(v3)으로 고정한다.

const goldenRuleset = "pqcota-enrich/v3"

// 옛 jvm 수집기가 내던 꼴 그대로다: 배포본 키 없이 ident를 컴포넌트 이름에 붙인다.
func legacyJCAResult() *discoveryv1.CollectionResult {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"cryptographic-asset","name":"jca-provider-chain@/opt/CryptoApp.java","properties":[
        {"name":"pqcota:crypto_runtime","value":"jca"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:jca.provider_set","value":"SUN,SunRsaSign,BC"},
        {"name":"pqcota:jca.registration_mode","value":"dynamic"},
        {"name":"pqcota:jca.pqc_services","value":"BC=ML-KEM-768|ML-DSA-65,SUN=,SunRsaSign="},
        {"name":"pqcota:app_keys","value":"/opt/CryptoApp.java"}]}]}`)
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{TargetNodeId: "pay-app", CollectorId: "jvm-collector",
			CollectedAt: timestamppb.New(time.Unix(1800000000, 0))},
		CbomCyclonedx: cbom,
	}
}

func legacyOpenSSLResult() *discoveryv1.CollectionResult {
	cbom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
      {"type":"library","name":"libssl.so.3","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.version","value":"3.0.13"},
        {"name":"pqcota:openssl.path","value":"/usr/lib/x86_64-linux-gnu/libssl.so.3"}]},
      {"type":"library","name":"libcrypto.so.3","properties":[
        {"name":"pqcota:crypto_runtime","value":"openssl"},
        {"name":"pqcota:detection_method","value":"runtime-introspection"},
        {"name":"pqcota:openssl.fork","value":"OpenSSL"},
        {"name":"pqcota:openssl.version","value":"3.0.13"}]}]}`)
	return &discoveryv1.CollectionResult{
		Envelope: &commonv1.Envelope{TargetNodeId: "pay-app", CollectorId: "openssl-collector",
			CollectedAt: timestamppb.New(time.Unix(1800000000, 0))},
		CbomCyclonedx: cbom,
	}
}

const (
	goldenJCAID           = "c61c591f135ff81f9113b5d0013db43df2293de42cdb2d0eb496f2b08f79a3ca"
	goldenOpenSSLPathID   = "b868d74d5a673e2cd763cd86333cb9a59e8973048e6532d654263d09bc9e798f"
	goldenOpenSSLNoPathID = "29a88656fdd022275a3b3392996954cac05e8f8a77e3c4625ec9daf16fe57f3e"
	goldenLegacyV1        = "57a9091b6ae21f6ccfcfee2962f3c7bf0c3cea3133e83aca103d7d2595bf7995"
	goldenLegacyDedupHash = "5c22ec9fc8709411275b66f3ff06c3cee561d229329b273e55f8d1d8a39bf24c"
)

func TestLegacyInputKeepsV011Identity(t *testing.T) {
	results := []*discoveryv1.CollectionResult{legacyJCAResult(), legacyOpenSSLResult()}
	snap, err := normalize.Normalize(results, "snap-golden", "pay-app", goldenRuleset, history.NewMemStore(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, f := range snap.Findings {
		switch {
		case f.GetJca() != nil:
			ids["jca"] = f.GetId()
		case f.GetOpenssl().GetPath() != "":
			ids["ssl-path"] = f.GetId()
		default:
			ids["ssl-nopath"] = f.GetId()
		}
	}
	for name, want := range map[string]string{"jca": goldenJCAID, "ssl-path": goldenOpenSSLPathID, "ssl-nopath": goldenOpenSSLNoPathID} {
		if ids[name] != want {
			t.Errorf("%s id = %s, want the v0.11.0 id %s", name, ids[name], want)
		}
	}
	if got := history.ContentHashV1(snap); got != goldenLegacyV1 {
		t.Errorf("ContentHashV1 = %s, want the v0.11.0 value %s", got, goldenLegacyV1)
	}
	if got := history.ContentHash(snap); got != goldenLegacyDedupHash {
		t.Errorf("ContentHash = %s, want the v0.11.0 value %s", got, goldenLegacyDedupHash)
	}
}
