[English](README.md) · 한국어

# cmd/: 인벤토리 진입점

인벤토리 단계의 CLI(Go 바이너리)입니다. 수집기가 관측한 것을 **중앙으로 적재하고**, 쌓인 것을 읽기 전용으로 **다시 읽습니다.** 다섯 범주로 나뉩니다.

## ① 적재: 가져온 결과를 이력에 쌓기

**`pqcota-ingest`는 디렉터리 하나에서** 수집기가 만든 `CollectionResult` JSON 파일을 읽어 범위 게이트 → 정규화 → 추가만 가능한 이력의 순서로 적재합니다. 아래 조회 명령이 읽는 데이터가 이렇게 만들어집니다.

파일을 그 디렉터리에 모으는 일은 **사용자의** 몫입니다. 데모에서는 Ansible이 각 노드에서 [수집기](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.ko.md#pqcota-hosts)를 실행하고 결과를 컨트롤러로 가져옵니다.

### `pqcota-ingest`

```
pqcota-ingest [-scope-assets <csv>] <results-dir> [scope-master-file]
pqcota-ingest -verify-keys <results-dir>
```

| 인자 · 옵션 | 하는 일 |
|---|---|
| `<results-dir>` | `*.json`(객체 하나)과 `*.jsonl`(한 줄 = 결과 하나)을 모두 읽습니다. **형식은 확장자가 아니라 내용으로 정합니다.** jvm attach 경로는 노드마다 JVM 여러 개를 JSONL로 내보냅니다. 입력 하나라도 해독하지 못하면 **적재하지 않고 멈춥니다.** 절반만 들어가면 빠진 자산과 원래 없는 자산을 구분할 수 없기 때문입니다 |
| `[scope-master-file]` | 노드 등록 게이트입니다. 주지 않으면 게이트를 건너뜁니다 |
| `-scope-assets <csv>` | 자산 범위: 등록된 노드 안에서 계속 관리할 자산만 남깁니다(아래) |
| `-verify-keys` | 수집기 ID에 묶은 키로 옮길 때 쓰는 점검입니다. 아무것도 저장하지 않고 등재 게이트도 적용하지 않습니다. 결과마다 수집기 ID, 서명 여부, 맞은 키의 지문, 판정을 출력합니다. 거부될 결과가 있으면 종료 상태 1입니다. [절차](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/environment-variables.ko.md#기존-배포를-결합-형식으로-옮기기) |

| 환경변수 | 하는 일 |
|---|---|
| `PQCOTA_DSN` | Postgres 접속 문자열입니다([형식](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.ko.md#pqcota-hosts)). 없으면 메모리 요약만 나오고 아무것도 저장하지 않습니다 |
| `PQCOTA_VERIFY_KEY` | 결과 서명을 검증할 키입니다. `<collector-id>:<공개 키>` 항목(쉼표로 구분)으로 적으면 결과마다 그 결과가 적은 수집기의 키로만 검증하고, **서명이 언제나 필수가 됩니다.** 공개 키만 나열하면 기존 형식입니다. 등록된 키 가운데 아무것으로나 맞으면 어느 수집기든 통과하고 경고를 냅니다. 값이 틀리면 결과를 읽기 전에 상태 2로 멈춥니다. 키 쌍은 [`pqcota-keygen`](https://github.com/randyinthedev-hash/pqcota-common/blob/main/cmd/README.ko.md#pqcota-keygen)이 만들고, 짝이 되는 개인 키는 **노드의 수집기가** 씁니다. [자세히](https://github.com/randyinthedev-hash/pqcota/blob/main/docs/environment-variables.ko.md#키를-수집기-id에-묶기) |
| `PQCOTA_REQUIRE_SIGNATURE` | `1`이면 확인할 키가 없을 때 **적재를 시작하지 않습니다.** 없으면 확인을 건너뛰지만 그 건수를 "서명 확인 안 함"으로 따로 보고합니다. 통과한 것과 같은 자리에 놓지 않습니다. 수집기 ID에 묶은 키를 쓰면 이 값과 상관없이 서명이 필수입니다 |
| `PQCOTA_ORG` | 이 적재가 속한 조직입니다(소문자, 숫자, 하이픈, 2–64자). 없으면 `default`에 묶입니다. **저장소를 여는 모든 명령이 같은 값을 보아야 합니다.** 읽는 쪽과 쓰는 쪽이 다르면 데이터는 있는데 보이지 않습니다 |
| `PQCOTA_REQUIRE_ORG` | `1`이면 조직 없이는 저장소를 열 수 없습니다. 이름으로 `default`도 쓸 수 없습니다(예약어입니다). 여러 조직이 저장소 하나를 나눠 쓰는 배포를 위한 것으로, 한번 섞이면 다시 나눌 수 없으므로 **여는 시점에** 막습니다 |
| `PQCOTA_AUTO_DDL` | `0`이면 이력 스키마를 만들지 않습니다. 이력 스키마가 없으면 오류로 멈춥니다. 메타데이터와 프로비저닝 기록 테이블은 그래도 만듭니다. 연결이 엉뚱한 곳을 가리킬 때 새 빈 테이블을 만들어 거기에 쓰는 일을 막습니다 |

> **`PQCOTA_DSN`을 주었는데 저장소를 열 수 없으면 멈춥니다.** v0.1.x는 메모리로 물러나 계속 진행했고,
> 그러면 화면에는 성공이 찍히는데 데이터는 프로세스와 함께 사라졌습니다. DSN을 준다는 것은 영속을 요청한다는 뜻입니다.

등록되지 않은 노드의 결과는 거부하고 저장하지 않습니다. **거부 기록**(노드, 수집기, 사유, 내용 지문)만 남기며, DB가 있으면 거기에 남습니다.

> **지금 구현이 노드의 최신 스냅샷을 만드는 방식.** 한 번의 적재에 나온 노드마다, **그 적재에 담긴 결과만으로** 최신 스냅샷을
> 만듭니다. 그 노드의 이전 스냅샷에 있던 항목이나 연결을 자동으로 이어 붙이지 않습니다. 그 적재에 나오지 않은 노드는
> 최신 스냅샷을 그대로 유지합니다.
>
> 그래서 한 노드의 결과를 일부만 적재하면(예: JVM 결과만), 제출하지 않은 자산과 연결이 최신 조회에서 빠지고
> 비교(`pqcota-inventory -diff`)에서 `removed`로 나타날 수 있습니다. 지금은 제출하지 않은 계층이 늘 갭으로 표시되지는
> 않습니다. 그러니 **이것을 자산이 제거되었다거나 연결이 없다는 증거로 읽지 마세요.** 이전 스냅샷은 이력에 남아 있고
> `-snapshot`으로 읽을 수 있습니다.
>
> 최신 조회가 빠짐없이 보이게 하려면, 한 노드에 대해 보여 주려는 결과를 같은 적재에 함께 넣으세요.
>
> ```
> # 여러 노드의 결과(OpenSSL, JVM, 네트워크)를 한 폴더에 모아 한 번에 적재
> ls results/
> pay-app-jca.jsonl  pay-app-net.json  pay-app-openssl.json  web-gw-net.json  web-gw-openssl.json ...
> pqcota-ingest results/
> ```

### `pqcota-declare-attribution`

```bash
pqcota-declare-attribution [--out <dir>] <attribution.csv>   # CSV: node_id,dst,app_key
pqcota-ingest <dir>                                          # load into the declaration lane
```

네트워크 관측은 **캡처하는 순간 소켓이 살아 있어야** 앱을 찾을 수 있습니다. 붙었다가 금방 끊기는 연결(배치 작업, 헬스 체크, cron, SSH)은 그 창 밖에 있어서 `app_key`가 빈 채로 남습니다. 조회 화면에 `@?`로 보이는 빈칸이 그것입니다. 운영자가 이 명령으로 그 빈칸을 채웁니다.

| | |
|---|---|
| `node_id` | 관측한 호스트(연결 간선의 src) |
| `dst` | 상대방. 연결 간선에 출력된 그대로입니다. `pqcota-inventory -snapshot`에 나옵니다. **포트를 따로 적지 마세요.** 계약이 `dst_addr`를 `"ip:port"`로 정의하므로 이미 들어 있고, 두 곳에 적으면 경고 없이 한쪽이 틀어질 수 있습니다 |
| `app_key` | 이 연결 간선을 연 앱 |

**그대로 실행해 볼 수 있는 샘플**은 [examples/inventory](../examples/inventory/README.ko.md#pqcota-declare-attribution-관측이-귀속하지-못한-연결-간선의-앱을-사람이-적기)([attribution.csv](../examples/inventory/attribution.csv))에 있습니다.

> **관측을 고치지 않습니다.** 선언은 자기만의 레인(`detection_method=UNSPECIFIED`)에 쌓이고,
> 합치는 일은 **조회할 때 화면에서** 일어납니다. 관측이 이미 찾은 앱은 덮어쓰지 않고 **빈칸만** 채우며,
> 채운 것은 `@app(declared)`로 건수와 함께 표시합니다.
>
> 저장소에서 둘을 나눠 두는 까닭은 두 가지입니다. 서명이 `app_key`를 포함하므로 고치면 수집기가 서명한 것과 달라지고,
> 원본에서 다시 계산하면 저장된 값과 달라집니다.

### 자산 범위 (`-scope-assets`)

노드를 등록했다고 **그 안에서 관측된 모든 것**이 관리 대상이 되지는 않습니다. 시스템 기본 라이브러리나 패키지가 끌어온 런타임이 섞이면 인벤토리가 잡음에 잠깁니다. 계속 지켜볼 것은 **사용자가 선언하고**, 도구는 그것을 강제합니다.

```csv
action,runtime,lib,app_key,note
exclude,*,*,/usr/bin/python*,the package's python runtime — not a managed target
exclude,openssl,libcrypto.so.*,*,exclude this whole family
include,openssl,libcrypto.so.3,/opt/apps/payment-gw,an exception for the payment gateway only
```

- 빈 셀과 `*`는 모두 "전부"를 뜻합니다. 패턴은 glob입니다. 규칙이 없으면 **전부 관리합니다**(기본이 포함).
- 판정 순서는 기본 포함 → `exclude`로 제거 → `include`로 복원입니다. **`include`가 `exclude`보다 우선하므로** "이 계열은 전부 빼되 이것만 남긴다"를 적을 수 있습니다.
- 공유 `.so`는 쓰는 앱이 여럿이므로, 그중 **하나라도 일치하면** 규칙이 적용됩니다.
- **제외는 "없음"이 아닙니다.** 적재 요약과 인벤토리 뷰가 몇 건을 뺐는지 알립니다. 알리지 않고 사라지면 인벤토리가 "그런 자산은 없다"고 거짓을 알리게 됩니다.

## ② CBOM 수용: 외부 도구가 만든 결과 가져오기

수집기가 **직접 관측하는** 런타임이라도 그 소스와 빌드 산출물은 **스캔하지 않고 위임합니다.** pqcota는 사용자의 CI에서 CBOMkit이 만든 표준 CycloneDX를 **받아서** 검증하고 정규화해 적재합니다. pqcota가 CBOMkit을 실행하지는 않습니다. → [discovery/README ②](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.ko.md)

### `pqcota-cbom-ingest`

```
pqcota-cbom-ingest <cbom.json | -> <target-node-id>
```

CycloneDX를 받아서 검증하고 적재합니다. 규격에 맞지 않으면 거부하고 저장하지 않습니다.

| 인자 | 하는 일 |
|---|---|
| `<cbom.json>` | 받을 CycloneDX 파일입니다. `-`는 표준 입력입니다(아래 CI 주입) |
| `<target-node-id>` | 그 CBOM을 어느 노드의 자산에 고정할지 정합니다 |

`env PQCOTA_DSN`이 있으면 Postgres에 영속하고, 없으면 메모리 요약만 출력합니다.

> **거부는 판단이 아니라 결정적인 검증입니다.** 지금 거부하는 이유는 하나입니다. **규격에 맞지 않는 구조**(깨진 JSON · CycloneDX(`bomFormat`)가 아님 · 지원하지 않는 `specVersion`)입니다. `ImportCBOM`은 서명 검증을 첫 게이트로 두지만, 이 명령에는 키를 줄 자리가 없어서 그 게이트가 서지 않으며, 명령은 실행할 때마다 stderr로 그렇게 알립니다. 둘 다 기계적으로 결정됩니다. 반대로 `target_node_id` 바인딩이 없는 것은 **거부가 아니고** 범위 판정으로 보내집니다. `pqcota:` 속성이 없는 자산도 **거부가 아니고**, 강도를 알 수 없는 채로 파싱하지 않을 뿐입니다. "믿을 수 없는 것은 버리되, 보지 못했다고 없다고 하지는 않는다."

`ImportCBOM`은 구조와 고정 대상을 검증합니다(서명 게이트는 연결되어 있지 않습니다. 위의 설명을 보세요). 통과한 것은 관측 레인(`detection_method=source/artifact`)을 거쳐 위와 같은 이력으로 모입니다. 어댑터: `pkg/inventory/ingest`.

> **`pqcota-ingest`에 적은 주의가 여기에도 해당합니다.** 런타임으로도 관측하는 노드 이름으로 외부 CBOM을 적재하면, CBOM의
> 항목만 담은 스냅샷이 그 노드의 최신 스냅샷이 됩니다. 런타임 스냅샷은 이력에 남지만, 최신 조회와 provisioning의 before 캡처는
> CBOM 스냅샷을 읽습니다. 최신 스냅샷을 대상으로 비교하면 CBOM 스냅샷과 비교하게 됩니다. 명시한 과거 스냅샷끼리의 비교는
> 영향을 받지 않습니다. 계획이 런타임 스냅샷을 명시해 가리키면 그 스냅샷을 그대로 찾습니다. CBOM을 런타임 조회에서 아예
> 떼어 두려면 소스 근거로 적재하세요(`--source-evidence`, 아래).

> **CI 파이프라인에서 주입하기**: CBOMkit의 출력을 중간 파일 없이 바로 파이프로 넘길 수 있습니다(GitHub Actions, GitLab CI 등).
> ```bash
> cbomkit scan ./repo | pqcota-cbom-ingest - cmdb://payment-gw
> ```
> CI는 무엇을 빌드하는지 알고 있으므로 여기서 `target-node-id`를 고정합니다(고정이 없으면 범위 판정으로 보내집니다. [pqcota-discovery README](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.ko.md)를 보세요).

### 소스 근거: `pqcota-cbom-ingest --source-evidence`

```
pqcota-cbom-ingest <cbom.json | -> [target-node-id] --source-evidence
                   [--preset <id>] [--source-map <file>] [--allow-unmatched-rules] [--dry-run] [--json]
```

`--source-evidence`를 주면 CBOM으로 스냅샷을 만들지 **않습니다.** CBOM이 보고한 암호 항목과 그 항목의 소스 위치를 검토용
**소스 근거**로 보관합니다. 런타임 조회, 이력, provisioning의 before 캡처는 바뀌지 않습니다. 이 플래그가 없으면 위에 적은 대로
동작합니다.

조직마다 한 트랜잭션으로 네 가지를 저장합니다. 받은 그대로의 CBOM, 쓴 매핑 파일(아래), 변환 결과, 수신 기록입니다. 같은 CBOM을
같은 매핑으로 다시 받으면 수신 기록만 하나 늡니다. 저장한 것은 [`pqcota-source-evidence`](#pqcota-source-evidence)로 읽습니다.

| 옵션 | 하는 일 |
|---|---|
| `[target-node-id]` | 선택입니다. 받은 값을 그대로 수신 기록에 적고, 스코프 마스터와 **대조하지 않습니다** |
| `--dry-run` | 변환해서 미리보기를 보여 줍니다. 아무것도 쓰지 않고 데이터베이스도 열지 않습니다 |
| `--json` | 기계가 읽는 출력입니다(`format: "pqcota-source-evidence/v1"`, `kind: "ingest"`). 저장했는지, 어디에 했는지(`storeKind`, `persistent`), 거부했다면 그 이유(`refusals`)를 담습니다 |
| `--preset <id>` | 내장 매핑을 적용합니다. 목록은 `pqcota-source-evidence --presets`로 봅니다 |
| `--source-map <file>` | 직접 쓴 매핑 파일을 적용합니다(최대 256 KiB) |
| `--allow-unmatched-rules` | 이 CBOM에서 하나도 맞지 않은 매핑 규칙을 받아들입니다. 그 규칙에서 나온 위치가 없을 뿐입니다 |

**무엇을 읽나.** `cryptographic-asset` 컴포넌트의 CycloneDX 표준 필드(이름, 자산 종류, OID, 알고리즘 속성,
`evidence.occurrences`)는 늘 읽습니다. 다른 컴포넌트는 세기만 합니다. `properties`는 도구가 낸 값으로 보관하고, pqcota의 판정으로
보이지 않습니다. 위치는 **검토할 보고 위치**로 보입니다. CBOM이 호출인지 선언인지 주석인지 말하지 않으므로 pqcota도 말하지
않습니다. 줄과 열은 보고된 값 그대로 보이고, 몇부터 세는지 알 때만 1부터 세는 값으로 바꿉니다. 표준 `line` 필드는 시작 값을
정하지 않으므로 보고된 값 그대로 보입니다.

**실제 도구 출력으로 확인한 것.** 표준 필드는 다음 도구들의 실제 출력으로 확인했습니다.

| 도구 | 입력 | pqcota가 읽은 것 | 어디까지 |
|---|---|---|---|
| CBOMkit(`cbomkit-action` v2.3.0) | 확인용으로 직접 작성한 Java 21 예제, CycloneDX 1.6 | 프리셋 없이 `evidence.occurrences.location`과 `line` | pqcota v0.12.0에서 계획이 고른 위치가 승인을 거쳐 생성 기록까지 같은 참조로 남았습니다(가이드가 있을 때와 없을 때 모두) |
| CBOMkit(`cbomkit-action` v2.3.0) | 확인용으로 직접 작성한 Python 3.13 예제(`pyca/cryptography` 50.0.2), CycloneDX 1.6 | 프리셋 없이 `evidence.occurrences.location`과 `line` | pqcota v0.12.0에서 계획이 고른 위치가 검토·서명·생성 기록까지 같은 참조로 남았습니다. 가이드 없이 확인했습니다 |
| CryptoScan 1.5.0 | 확인용으로 직접 작성한 C 예제(OpenSSL 3 EVP), CycloneDX 1.6 | 프리셋 없이 `evidence.occurrences.location`과 `line`(도구의 `symbol`도 보존) | pqcota v0.12.0에서 같습니다. 가이드 없이 확인했습니다(이 코드에 맞는 가이드가 카탈로그에 없습니다) |

CBOMkit, Java 예제:

- CBOM에 들어 있던 위치는 14개입니다. 예제에 기대 위치로 표시해 둔 호출 여섯 곳은 모두 그 줄 그대로 보고됐습니다.
- 경로와 줄은 도구가 보고한 값 그대로 보존됩니다. 경로는 도구에 소스를 붙인 자리(`ws/`)로 시작하고, 줄은 몇부터 세는지 적혀 있지 않아 모름으로 보입니다.
- **이번 실행의 한계:** 알고리즘 이름을 변수로 넘긴 키 생성기는 보고되지 않았고, 256비트 AES-GCM 키를 128비트로 보고했습니다. **이전 실행에서 본 것**(2026-11-10, 같은 판, 다른 코드): Bouncy Castle 경량 API(`MLKEMGenerator` 등) 호출이 보고되지 않았습니다.

CBOMkit, Python 예제:

- 통합 CBOM의 `evidence.occurrences`에 들어 있던 위치 6개를 프리셋 없이 모두 읽었습니다. 이 위치들이 가리킨 서로 다른 소스 줄은 3곳이고, 모두 키 생성 호출입니다(AES-GCM 키, RSA-3072 키, EC P-256 키).
- 계획에서 참조한 위치는 27행의 RSA-3072 키 생성이고, 그 참조가 검토·서명·생성 기록까지 유지됐습니다.
- **이번 실행의 한계:** 이 예제에서는 암호화, RSA-OAEP 문서 키 감싸기, 서명, 해시 호출이 보고되지 않았습니다.

CryptoScan, C 예제:

- CBOM에 들어 있던 위치는 3개입니다. 기대 위치 가운데 두 곳이 그 줄 그대로 보고됐습니다. 키 생성 호출 둘이고, 알고리즘 이름 문자열 `"RSA"`와 `"P-256"` 자리입니다.
- **이번 실행의 한계:** OpenSSL EVP 호출(AES-GCM 암호화, RSA-OAEP 키 감싸기, ECDSA 서명)은 보고되지 않았고, `#include <openssl/rsa.h>` 줄이 위치로 보고됐습니다. 2026-11-10에 같은 판, 같은 입력으로 돌렸을 때도 같았습니다.
- C만 확인했습니다. C++는 확인하지 않았습니다.

각 행은 도구 판 하나가 예제 하나에서 보고한 결과입니다. 도구의 탐지 범위를 말하는 것이 아닙니다.

**매핑.** 소스 위치를 `evidence.occurrences`가 아니라 `properties`에 넣는 도구가 있습니다. 매핑은 그 위치를 어디서 읽을지
알려 줍니다. 내장 프리셋은 둘입니다.

| 프리셋 | 확인한 출력 | 읽는 것 |
|---|---|---|
| `cdxgen-dotnet-sourcelocation@1` | cdxgen 13.7.0, .NET 8 프로젝트 | `cdx:crypto:sourceLocation`(`path:line:column`, 컴포넌트마다 여러 개) |
| `dosai-cyclonedx-location@1` | dosai 5.0.0.0 CycloneDX 출력, .NET 8 프로젝트 | `cryptographic-asset` 컴포넌트의 `dosai:location` |

프리셋은 표에 적은 도구 판으로만 확인했습니다. 둘 다 줄은 1부터 세고, 열은 시작 값과 단위가 `unknown`이라 보고된 값 그대로
보입니다. 다른 도구라면 매핑 파일을 씁니다.

```json
{
  "format": "pqcota-source-map/v1",
  "id": "my-scanner",
  "revision": "1",
  "rules": [
    {
      "id": "source-location",
      "componentTypes": ["cryptographic-asset"],
      "locations": {
        "from": "component",
        "combined": {"property": "my:sourceLocation", "each": true, "parser": "path:line:column"},
        "lineBase": 1,
        "columnBase": "unknown",
        "columnUnit": "unknown"
      }
    }
  ]
}
```

- `combined`는 값 하나에 위치 전체가 든 property를 읽습니다. 파서는 `path:line`과 `path:line:column`입니다. 숫자를 오른쪽부터
  떼므로 `C:\src\a.cs:12:5`도 읽힙니다. `"each": true`가 없는데 한 컴포넌트에 값이 여럿이면 오류입니다.
- `combined` 대신 `file`(필요하면 `line`, `column`도)로 값을 따로 읽을 수 있습니다. 각각 `{"property": "<이름>"}`이나
  `{"pointer": "<컴포넌트 안의 JSON Pointer>"}`로 적습니다. `"array": "<pointer>"`를 더하면 배열의 요소마다 위치를 하나씩 읽습니다.
- `lineBase`는 꼭 적습니다. `0`, `1`, `"unknown"` 가운데 하나입니다. 열을 읽으면 `columnBase`와 `columnUnit`(`byte`, `utf16`,
  `codepoint`, `unknown`)도 적습니다. 확인하지 않았으면 `"unknown"`이라고 적으세요. 그 값은 바꾸지 않고 보고된 그대로 보입니다.
- 모르는 키나 다른 `format` 판은 거부합니다. 파일을 고칠 때마다 `revision`을 올리세요.

**거부할 때.** 지정한 매핑은 오류 없이 변환돼야 합니다. 하나여야 할 값이 여럿이거나, 파서의 꼴에 맞지 않거나, 필드가 빠졌거나,
줄이나 열이 잘못됐으면 **아무것도 저장하지 않습니다**(종료 코드 1, 미리보기도 1). 어느 컴포넌트에도 맞지 않은 규칙도 거부합니다.
`--allow-unmatched-rules`를 주면 받아들입니다. 매핑 파일이 잘못됐거나 없는 프리셋이면 CBOM을 변환하기 전에 멈춥니다(종료 코드 2).
모르는 옵션도 종료 코드 2로 멈추므로, 플래그를 잘못 적어도 스냅샷을 쓰는 쪽으로 넘어가지 않습니다.

**크기 상한.** CBOM은 32 MiB, 매핑 파일은 256 KiB까지입니다. 이보다 크면 끝까지 읽지 않고 멈춥니다. CBOM이 넘으면 종료 코드 1,
매핑 파일이 넘으면 다른 잘못된 매핑과 같이 종료 코드 2입니다. 어느 쪽이든 아무것도 저장하지 않습니다.

```bash
# 먼저 보고, 그다음 저장
pqcota-cbom-ingest cbom.json --source-evidence --preset cdxgen-dotnet-sourcelocation --dry-run
pqcota-cbom-ingest cbom.json web-01 --source-evidence --preset cdxgen-dotnet-sourcelocation
```

`env PQCOTA_DSN`이 있으면 Postgres에 저장합니다. 없으면 메모리에만 두고, 명령이 끝나면 사라집니다. 어느 쪽인지 출력에 나옵니다.

## ③ 조회: 쌓인 것을 읽기 전용으로 읽기

핵심 구분은 **파일 대조(휘발성, 로컬)와 중앙 저장소 조회(영속, 별도 프로세스)**입니다.

### `pqcota-discover-view`

```
pqcota-discover-view <results-dir> [nodes.json] [topology-out.dot]
```

| 인자 | 하는 일 |
|---|---|
| `<results-dir>` | 가져온 `CollectionResult` JSON 파일을 그 자리에서 대조합니다 |
| `[nodes.json]` | 관측된 IP를 노드 이름에 대응시킵니다(`10.0.0.9` → `node-c`) |
| `[topology-out.dot]` | 통신 토폴로지를 DOT으로 씁니다(색 = 등급) |

발견한 자산(OpenSSL, JCA)과 관측된 통신 연결 간선마다의 등급을 출력합니다. **저장소를 쓰지 않습니다.** 휘발성 뷰입니다.

### `pqcota-inventory`

```
pqcota-inventory [-history <node>] [-snapshot <id>] [-diff <past-id>,<latest-id>]
```

인자 없이 실행하면 **모든 노드의 최신 스냅샷 + 등급 집계**를 출력합니다. `▸` 시스템 헤더(엔드포인트와 프로필)와 `@` 앱 라벨(공유 `.so`는 여럿이 보입니다)이 붙습니다. `env PQCOTA_DSN`이 필요합니다(Postgres의 추가만 가능한 이력과 시스템 메타데이터를 읽습니다).

| 플래그 | 하는 일 |
|---|---|
| `-history <node>` | 그 노드의 스냅샷을 **오래된 것부터** 나열합니다: 순번, 적재 시각, 규칙 세트, 발견 항목과 연결 간선 수, 갭 |
| `-snapshot <id>` | **스냅샷 하나의 상세**: 자산 표 + 그 스냅샷의 **관측된 연결 간선**(누적 뷰는 합계만 출력하므로 여기서만 펼쳐집니다) |
| `-diff <past-id>,<latest-id>` | 두 스냅샷 사이의 **변경**: `added`, `removed`, `changed` |

**`-diff`의 방향 규약: 첫 번째 인자 = 과거, 두 번째 = 최신**입니다(`added` = 두 번째에만 있음, `removed` = 첫 번째에만 있음). 시간 순서를 거꾸로 주면 방향이 반대로 읽히므로 **거꾸로 주면 경고합니다.** 발견 항목 id는 (노드, 이름, 런타임, fork, OpenSSL은 입력에 있으면 라이브러리 경로까지)의 해시입니다. 그래서 **버전이 바뀌어도 같은 자산의 `changed`로 잡히고**, 한 노드에 파일 이름이 같은 설치본이 둘이면 자산 둘로 남습니다. 규칙 세트가 다르면 파생 값의 차이가 재계산의 결과일 수 있다고 경고합니다.

**스냅샷은 변경 시점에만 쌓입니다.** 같은 상태를 다시 관측하면 새 스냅샷을 만들지 않고 **관측 기록**(가벼움)만 남기므로, `-history`의 `obs`와 `observed` 열이 "그 상태를 몇 번, 언제까지 다시 확인했는가"를 보여 줍니다. 그래서 무거운 저장은 **변경 횟수만큼만** 늘고, "매번 스캔했다"는 증거는 남습니다.

**최신 스냅샷은 맨 아래 행이 아니라 마지막으로 적재한 상태입니다.** 전에 본 상태가 다시 오면 그때의 스냅샷을 다시 쓰므로, 내용이 A → B → A로 바뀌면 스냅샷은 A와 B 둘이고 노드는 A 상태입니다. 노드의 최신 스냅샷은 가장 최근 관측 기록이 가리키는 스냅샷입니다. 인자 없는 조회, 적재 요약, 전환물 생성의 변경 전 기록이 모두 이것을 읽습니다. `-history`는 그 행에 `← current (last ingested)`를 붙입니다. 관측 기록 없이 쓴 이력이면 가장 나중 스냅샷을 씁니다.

### `pqcota-source-evidence`

```
pqcota-source-evidence [--limit N] [--json]
pqcota-source-evidence --id <interpretation-id> [--json]
pqcota-source-evidence --input <sha256> --out <file>
pqcota-source-evidence --map <sha256> --out <file>
pqcota-source-evidence --presets [--json]
```

`pqcota-cbom-ingest --source-evidence`가 저장한 소스 근거를 읽습니다. 읽기만 하고 테이블을 만들지 않으므로 `SELECT` 권한만 있는
계정으로도 됩니다. `--presets`를 빼면 `env PQCOTA_DSN`이 필요합니다.

| 플래그 | 하는 일 |
|---|---|
| (없음) | 저장한 변환 결과를 최근 것부터 보여 줍니다. CycloneDX 판, CBOM이 밝힌 도구, 쓴 매핑, 항목·위치 수, 받은 횟수, 사용자가 지정한 대상 노드가 나옵니다. 받은 횟수는 변환 결과마다 최근 100건까지 셉니다. 그보다 많으면 「100번 넘게」로 적고, 대상 노드도 최근 100건에서 모은 것입니다 |
| `--id <id>` | 변환 결과 하나의 최근 수신 기록 100건과 항목, 보고 위치를 보여 줍니다. 그보다 오래된 수신 기록이 있으면 그렇다고 알립니다(`--json`에서는 `receiptsTruncated: true`). 같은 위치가 여러 번 보고되면 한 줄로 보이고, 원본 포인터는 그 아래에 모두 나옵니다 |
| `--input <sha256> --out <file>` | 받은 그대로의 CBOM을 새 파일로 씁니다. 해시를 먼저 확인하고, 있는 파일은 덮어쓰지 않으며, 터미널에는 찍지 않습니다 |
| `--map <sha256> --out <file>` | 변환에 쓴 매핑 파일을 같은 방식으로 씁니다 |
| `--presets` | 내장 매핑과 그 매핑을 확인한 출력을 보여 줍니다 |
| `--json` | `format: "pqcota-source-evidence/v1"`, `kind`는 `"interpretations"`, `"interpretation"`, `"presets"` 가운데 하나입니다. 상세는 위치를 묶지 않은 그대로 내고, 화면에서 묶은 방식은 `displayGroups`로 따로 알려 줍니다 |

경로, 기호, 문맥은 CBOM에서 온 값입니다. 제어 문자를 이스케이프해 글자로만 보이고, 무엇을 열거나 실행하지 않습니다. 다른
조직(`PQCOTA_ORG`)의 근거는 보이지 않습니다.

## ④ 보존 정책: 오래된 변경 시점 잘라내기

### `pqcota-prune`

```
pqcota-prune [-older-than 90d] [-keep-last N] [-apply]
```

| 플래그 | 하는 일 |
|---|---|
| `-older-than <duration>` | 이보다 오래된 변경 시점을 잘라냅니다(예: `90d`, `720h`) |
| `-keep-last <N>` | 노드마다 가장 최근 변경 시점 N개를 남깁니다 |
| `-apply` | 실제로 삭제합니다. **없으면 계획만 보여 줍니다**(기본이 드라이런) |

두 축을 모두 주면 판정은 **보수적**입니다(둘 다 버려도 된다고 할 때만 버립니다). 정책이 하나도 없으면 거부합니다.

불변 조건이 셋 있습니다. **최신은 건드리지 않고**(노드마다 최신 스냅샷, 곧 마지막으로 적재한 상태와 가장 나중 변경 시점은 어떤 정책으로도 삭제되지 않습니다. 인벤토리 뷰와 전환물 생성의 변경 전 기록이 최신 스냅샷을 기준으로 삼습니다), **수정하지 않고**(남은 스냅샷은 바이트 단위로 그대로입니다), **잘라낸 사실을 기록합니다**(`-history`가 `⌫` 줄로 알립니다. 없으면 이력의 빈 구간이 "관측하지 못함"으로 읽힙니다). 조회 명령과는 **일부러 분리했습니다.** 읽기 도구가 파괴적인 동작까지 하면 실수 한 번에 이력이 지워집니다.

## ⑤ 메타데이터 · 선언 가져오기

엔드포인트는 `pqcota-hosts --dsn`(pqcota-discovery)이 채우고, 프로필과 선언은 아래 두 명령이 채웁니다. → [수집기와 접근 준비 명령 지도](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.ko.md#pqcota-hosts)

### `pqcota-profile`

```
pqcota-profile [--dsn <postgres>] <profiles.csv>
```

| 인자 · 옵션 | 하는 일 |
|---|---|
| `<profiles.csv>` | 시스템 프로필(`display_name`, `environment`, `role`, `owner`, `location`, `labels`)입니다. 원천은 CMDB입니다 |
| `--dsn <postgres>` | 주면 `PQCOTA_ORG`가 가리키는 조직(설정하지 않았으면 기본 조직)으로 인벤토리에 upsert합니다. 없으면 파싱 결과만 보여 줍니다 |

식별과 분리해 둔 **사람을 위한 메타데이터**입니다. 뷰의 `▸` 헤더를 채웁니다.

### `pqcota-declare`

```
pqcota-declare [--out <dir>] <declaration.csv>
```

| 인자 · 옵션 | 하는 일 |
|---|---|
| `<declaration.csv>` | 사용자가 선언한 인벤토리(`node_id`, `crypto_runtime`, `component`)입니다 |
| `--out <dir>` | `CollectionResult` JSON의 출력 디렉터리입니다(기본값 `declared-results`) |

**관측이 아닙니다.** `detection_method`는 비워서 나갑니다. 만들어 낸 JSON을 `pqcota-ingest <dir>`(①)로 적재하면 대조의 기준선이 됩니다.

## 무엇을 언제 쓰나
- 가져온 결과 파일을 **한 번 대조해 그 자리에서 보려면** → **`pqcota-discover-view`**(저장소 불필요, 휘발성).
- **여러 노드가 시간에 걸쳐 쌓은 누적 인벤토리를 중앙에서 조회하려면**(엔드포인트, 프로필, 앱 라벨 포함) → **`pqcota-inventory`**(Postgres).
- **외부 CBOM을 실행 중인 것과 떼어 검토할 소스 위치로 두려면** → **`pqcota-cbom-ingest --source-evidence`**, 읽을 때는 **`pqcota-source-evidence`**.

> 로직은 `pkg/inventory/`에 있고(적재 어댑터 `ingest`, 뷰 렌더링, `RenderStore`, 시스템 메타데이터 `MetaStore`, hosts 파서), 정규화와 이력 저장소도 거기에 포함됩니다. 이 명령들은 그것을 조립하는 얇은 진입점입니다.
