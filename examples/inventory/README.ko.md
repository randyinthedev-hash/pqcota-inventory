[English](README.md) · 한국어

# examples/inventory: 읽기 전용 인벤토리 뷰

```bash
./examples/inventory/run.sh
```

## 무슨 일이 일어나는가

### `pqcota-discover-view`: 결과를 대조해 자산 + 앱 + 등급 보기

> 샘플에는 **Windows CNG 노드(`node-d`)**가 하나 들어 있습니다. 리눅스 수집기 세 개 옆에 있어서,
> 런타임이 늘어도 뷰가 같은 자리에 그리는 것을 여기서 볼 수 있습니다. 그 노드의 줄에는 provider 수,
> 알고리즘 수, PQC 요약(`native (signature only — no KEM observed)`)이 붙습니다.

[`../data/results`](../data)의 `CollectionResult` JSON 파일을 모아서 **발견한 자산**과 **관측된 통신 연결 간선마다의 등급**을 보여 줍니다(파일 대조, 휘발성, 저장소 불필요). 비교하거나 대조(reconcile)하지는 않습니다.

예상 출력(요지):
```
──────── ① discovered assets (per node) ────────
  node-a
    • OpenSSL  libssl.so.3 3.0.13 (OpenSSL) [EVIDENCE_STRENGTH_CONFIRMED]
  node-b
    • JCA provider chain: SUN,SunJCE,BC [EVIDENCE_STRENGTH_CONFIRMED]

──────── ② observed edges + quantum-resistance grade ────────
  🟢 node-a      → node-b             TLS   X25519MLKEM768 [fips-standard]
  🔴 node-a      → node-c             TLS   x25519
  🟢 node-a      → node-b             SSH   sntrup761x25519-sha512@openssh.com [experimental]

  grade totals: 🟢 PQC 2 · 🔴 classical 1 · ⚪ unknown 0
```
- **등급**: 🟢 PQC/하이브리드 · 🔴 고전 = 양자 취약 · ⚪ 등급 미정. PQC 그룹에는 성숙도(`fips-standard`/`draft`/`experimental`/`broken`)도 함께 붙습니다.
- **IP와 노드 연결**: `nodes.json`이 `10.0.0.9` → `node-c`로 대응시킵니다(연결 간선의 `dstAddr`가 이름으로 보입니다).
- 토폴로지 **DOT** 파일도 만들어집니다(색 = 등급). `dot -Tsvg`로 SVG로 렌더링하세요.

> 앱 라벨(`@app`)과 엔드포인트·프로필 헤더는 **중앙 영속 뷰**(`pqcota-inventory`, Postgres)에서 함께 보입니다. 이 파일 대조 뷰는 자산과 연결 간선이 중심입니다.

### `pqcota-declare-attribution`: 관측이 귀속하지 못한 연결 간선의 앱을 사람이 적기

네트워크 관측은 **캡처하는 순간 소켓이 살아 있어야** 연결을 연 앱을 찾을 수 있습니다. 붙었다가
금방 끊기는 연결(배치 작업, 헬스 체크, cron, SSH)은 그 창 밖에 있어서 `app_key`가 빈 채로 남고 조회 화면에
`@?`로 보입니다. **그것은 "어느 앱인지 알 수 없었다"는 뜻이지 "앱이 없다"는 뜻이 아니며**, 운영자가
이 명령으로 그 빈칸을 채웁니다.

입력은 파일 하나, [`attribution.csv`](attribution.csv)입니다.

```csv
node_id,dst,app_key
node-a,10.0.0.9:443,nightly-sync.service
```

| 열 | 내용 |
|---|---|
| `node_id` | 관측한 호스트, 곧 연결 간선의 src |
| `dst` | 상대방. 연결 간선에 출력된 주소 그대로 씁니다. 계약이 `dst_addr`를 `"ip:port"`로 정의하므로 포트가 이미 들어 있고, **포트를 따로 적지 않습니다** |
| `app_key` | 이 연결 간선을 연 앱 |

첫 줄의 첫 셀이 `node_id`이면 헤더로 보고 건너뜁니다. 세 값 중 하나라도 비어 있으면
줄 번호를 알리고 **멈춥니다.** 어느 연결 간선의 것인지 모르고 앱을 가리키면 조치하는 대상이 달라지기 때문입니다.

**`dst`는 `pqcota-inventory -snapshot` 화면에서 복사하세요.** 위 샘플에서 그 연결 간선은 이 파일 대조 뷰에
`node-a → node-c`로 나오지만, 그것은 `nodes.json`이 읽기 좋게 IP를 이름으로 바꾼 것이고
연결 간선이 실제로 가진 값은 `10.0.0.9:443`입니다. 선언이 맞춰야 하는 것은 가진 값입니다. 상대방이
범위 마스터의 노드에 연결되어 있고 주소가 비어 있다면 그 `node_id`를 적습니다.

**키는 (관측한 호스트, 상대방) 둘뿐입니다.** 프로토콜과 포트는 키에 없으므로, 같은 상대에게 가는 연결 간선이
여럿이면(예: 같은 노드로 가는 TLS와 SSH) 한 줄이 모두 채웁니다.

```bash
pqcota-declare-attribution --out ./declared-attr examples/inventory/attribution.csv
pqcota-ingest ./declared-attr
```

첫 줄이 만드는 것은 **선언 레인의 `CollectionResult`**(`detection_method` 없음 = UNSPECIFIED)입니다.
`run.sh`가 그 JSON을 그대로 출력하므로 무엇이 만들어지는지 볼 수 있습니다.

> **관측을 고치지 않습니다.** 선언은 자기만의 레인에 쌓이고 관측된 연결 간선은 그대로입니다. 둘을 합치는 일은
> **조회할 때 화면에서** 일어나며, 관측이 이미 찾은 앱은 덮어쓰지 않고 빈칸만 채웁니다. 채운 것은
> `@app(declared)`로 표시합니다. 저장소에서 둘을 나눠 두는 까닭은 두 가지입니다. 서명이 `app_key`를 포함하므로
> 고치면 수집기가 서명한 것과 달라지고, 원본에서 다시 계산하면 저장된 값과 달라집니다.
>
> **합쳐진 화면은 `pqcota-inventory`(Postgres)에서만 나타납니다.** 층을 겹치는 오버레이가 선언 저장소를 읽으므로,
> 저장소가 없는 이 파일 대조 뷰(`pqcota-discover-view`)는 그 단계에 이르지 않습니다. 끝까지 보려면 아래의
> 중앙 영속 조회를 쓰거나 [demo/](https://github.com/randyinthedev-hash/pqcota/blob/main/demo/README.ko.md)를 실행하세요.

## 중앙 영속 조회 (`pqcota-inventory`)
파일 대조가 아니라 **여러 노드가 시간에 걸쳐 쌓은 인벤토리**를 조회하려면 Postgres가 필요합니다.
```bash
# first load into the same DSN (pqcota-ingest), then:
PQCOTA_DSN=postgres://… go run ./cmd/pqcota-inventory
```
→ ▸ 엔드포인트와 프로필 헤더, `@` 앱 라벨(공유 .so는 여럿이 보입니다)까지 나옵니다. 처음부터 끝까지의 흐름은 [demo/](https://github.com/randyinthedev-hash/pqcota/blob/main/demo/README.ko.md)를 보세요. 명령 지도: [cmd/README](../../cmd/README.ko.md).

### `pqcota-cbom-ingest`: 외부 도구가 만든 CBOM 받기
수집기가 관측하지 않는 소스와 빌드 산출물은, 사용자의 CI에서 **CBOMkit** 등이 만든 표준 CycloneDX를 **받아서** 적재합니다. [`sample-cbom.json`](sample-cbom.json)을 넣으면 이렇게 나옵니다.
```
✓ accepted: node=node-b · detection_method=source/artifact · 1 assets · store in-memory (summary only — gone when the process exits)
```
- **검증(구조와 고정 대상)은 명령 안에서 강제됩니다.** 규격에 맞지 않는 CBOM은 거부되고 저장되지 않습니다. 따로 사전 점검할 필요가 없습니다. 서명 게이트는 연결되어 있지 않으며, 명령은 실행할 때마다 그렇게 알립니다.
- 관측 레인(`detection_method=source/artifact`)으로 붙고 **수집기 관측과 같은 인벤토리로 모입니다**(Postgres에 영속한 경우).

> **샘플의 모양에 관한 참고**: 정규화는 지금 CBOM의 **`pqcota:` 속성**을 읽습니다([`sample-cbom.json`](sample-cbom.json)이 그 모양이며, 소스에서 JCA/BouncyCastle을 찾은 것처럼 만들었습니다). CBOMkit 표준 출력(`cryptoProperties`)을 pqcota 스키마에 대응시키는 것은 가져오기 어댑터의 **확장 지점**입니다. 지금은 pqcota 쪽으로 대응된 CBOM만 자산으로 파싱합니다.
