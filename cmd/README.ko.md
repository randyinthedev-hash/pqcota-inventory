[English](README.md) · 한국어

# cmd/: 인벤토리 진입점

인벤토리 단계의 CLI(Go 바이너리)입니다. 수집기가 관측한 것을 **중앙으로 적재하고**, 쌓인 것을 읽기 전용으로 **다시 읽습니다.** 다섯 범주로 나뉩니다.

## ① 적재: 가져온 결과를 이력에 쌓기

**`pqcota-ingest`는 디렉터리 하나에서** 수집기가 만든 `CollectionResult` JSON 파일을 읽어 범위 게이트 → 정규화 → 추가만 가능한 이력의 순서로 적재합니다. 아래 조회 명령이 읽는 데이터가 이렇게 만들어집니다.

파일을 그 디렉터리에 모으는 일은 **사용자의** 몫입니다. 데모에서는 Ansible이 각 노드에서 [수집기](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.ko.md#pqcota-hosts)를 실행하고 결과를 컨트롤러로 가져옵니다.

### `pqcota-ingest`

```
pqcota-ingest [-scope-assets <csv>] <results-dir> [scope-master-file]
```

| 인자 · 옵션 | 하는 일 |
|---|---|
| `<results-dir>` | `*.json`(객체 하나)과 `*.jsonl`(한 줄 = 결과 하나)을 모두 읽습니다. **형식은 확장자가 아니라 내용으로 정합니다.** jvm attach 경로는 노드마다 JVM 여러 개를 JSONL로 내보냅니다. 입력 하나라도 해독하지 못하면 **적재하지 않고 멈춥니다.** 절반만 들어가면 빠진 자산과 원래 없는 자산을 구분할 수 없기 때문입니다 |
| `[scope-master-file]` | 노드 등록 게이트입니다. 주지 않으면 게이트를 건너뜁니다 |
| `-scope-assets <csv>` | 자산 범위: 등록된 노드 안에서 계속 관리할 자산만 남깁니다(아래) |

| 환경변수 | 하는 일 |
|---|---|
| `PQCOTA_DSN` | Postgres 접속 문자열입니다([형식](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/cmd/README.ko.md#pqcota-hosts)). 없으면 메모리 요약만 나오고 아무것도 저장하지 않습니다 |
| `PQCOTA_VERIFY_KEY` | 공개 키(쉼표로 구분)입니다. 있으면 결과 서명을 확인하고 맞지 않으면 거부합니다. 키 쌍은 [`pqcota-keygen`](https://github.com/randyinthedev-hash/pqcota-common/blob/main/cmd/README.ko.md#pqcota-keygen)이 만들고, 짝이 되는 개인 키는 **노드의 수집기가** 씁니다 |
| `PQCOTA_REQUIRE_SIGNATURE` | `1`이면 확인할 키가 없을 때 **적재를 시작하지 않습니다.** 없으면 확인을 건너뛰지만 그 건수를 "서명 확인 안 함"으로 따로 보고합니다. 통과한 것과 같은 자리에 놓지 않습니다 |
| `PQCOTA_ORG` | 이 적재가 속한 조직입니다(소문자, 숫자, 하이픈, 2–64자). 없으면 `default`에 묶입니다. **저장소를 여는 모든 명령이 같은 값을 보아야 합니다.** 읽는 쪽과 쓰는 쪽이 다르면 데이터는 있는데 보이지 않습니다 |
| `PQCOTA_REQUIRE_ORG` | `1`이면 조직 없이는 저장소를 열 수 없습니다. 이름으로 `default`도 쓸 수 없습니다(예약어입니다). 여러 조직이 저장소 하나를 나눠 쓰는 배포를 위한 것으로, 한번 섞이면 다시 나눌 수 없으므로 **여는 시점에** 막습니다 |
| `PQCOTA_AUTO_DDL` | `0`이면 스키마를 만들지 않습니다. 없으면 오류로 멈춥니다. 연결이 엉뚱한 곳을 가리킬 때 새 빈 테이블을 만들어 거기에 쓰는 일을 막습니다 |

> **`PQCOTA_DSN`을 주었는데 저장소를 열 수 없으면 멈춥니다.** v0.1.x는 메모리로 물러나 계속 진행했고,
> 그러면 화면에는 성공이 찍히는데 데이터는 프로세스와 함께 사라졌습니다. DSN을 준다는 것은 영속을 요청한다는 뜻입니다.

등록되지 않은 노드의 결과는 버리지 않고 **등록 요청**으로 남깁니다.

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

> **CI 파이프라인에서 주입하기**: CBOMkit의 출력을 중간 파일 없이 바로 파이프로 넘길 수 있습니다(GitHub Actions, GitLab CI 등).
> ```bash
> cbomkit scan ./repo | pqcota-cbom-ingest - cmdb://payment-gw
> ```
> CI는 무엇을 빌드하는지 알고 있으므로 여기서 `target-node-id`를 고정합니다(고정이 없으면 범위 판정으로 보내집니다. [pqcota-discovery README](https://github.com/randyinthedev-hash/pqcota-discovery/blob/main/README.ko.md)를 보세요).

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

**`-diff`의 방향 규약: 첫 번째 인자 = 과거, 두 번째 = 최신**입니다(`added` = 두 번째에만 있음, `removed` = 첫 번째에만 있음). 시간 순서를 거꾸로 주면 방향이 반대로 읽히므로 **거꾸로 주면 경고합니다.** 발견 항목 id는 (노드, 이름, 런타임, fork)의 해시라서 **버전이 바뀌어도 같은 자산의 `changed`로 잡힙니다.** 규칙 세트가 다르면 파생 값의 차이가 재계산의 결과일 수 있다고 경고합니다.

**스냅샷은 변경 시점에만 쌓입니다.** 같은 상태를 다시 관측하면 새 스냅샷을 만들지 않고 **관측 기록**(가벼움)만 남기므로, `-history`의 `obs`와 `observed` 열이 "그 상태를 몇 번, 언제까지 다시 확인했는가"를 보여 줍니다. 그래서 무거운 저장은 **변경 횟수만큼만** 늘고, "매번 스캔했다"는 증거는 남습니다.

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

불변 조건이 셋 있습니다. **최신은 건드리지 않고**(노드마다 최신은 어떤 정책으로도 삭제되지 않습니다. 인벤토리 뷰와 전환물 생성의 변경 전 기록이 그것을 기준으로 삼습니다), **수정하지 않고**(남은 스냅샷은 바이트 단위로 그대로입니다), **잘라낸 사실을 기록합니다**(`-history`가 `⌫` 줄로 알립니다. 없으면 이력의 빈 구간이 "관측하지 못함"으로 읽힙니다). 조회 명령과는 **일부러 분리했습니다.** 읽기 도구가 파괴적인 동작까지 하면 실수 한 번에 이력이 지워집니다.

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

> 로직은 `pkg/inventory/`에 있고(적재 어댑터 `ingest`, 뷰 렌더링, `RenderStore`, 시스템 메타데이터 `MetaStore`, hosts 파서), 정규화와 이력 저장소도 거기에 포함됩니다. 이 명령들은 그것을 조립하는 얇은 진입점입니다.
