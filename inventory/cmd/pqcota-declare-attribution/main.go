// Command pqcota-declare-attribution — 사람이 지정한 **엣지의 앱**을 선언 레인으로 임포트한다.
//
// 왜 필요한가: 네트워크 관측은 캡처하는 순간 소켓이 살아 있어야 앱을 알아낸다. 짧게 붙었다
// 끊기는 연결(배치·헬스체크·cron·SSH)은 그 구간을 벗어나므로 `app_key`가 빈다. 그 자리를 운영자가
// 메우는 길이다.
//
//	입력 CSV: node_id,dst,app_key
//	  node_id — 관측 호스트(엣지의 src)
//	  dst     — 상대. 엣지에 찍힌 주소 그대로(`pqcota-inventory -snapshot`에서 보인다).
//	            계약이 `dst_addr`를 "ip:port"로 정하므로 포트가 이미 들어 있다.
//
// usage: pqcota-declare-attribution [--out <dir>] <attribution.csv>
//
//	→ 이후: pqcota-ingest <dir>   (선언 레인이 히스토리에 적재된다)
//
// **관측을 고치지 않는다.** 이 선언은 자기 레인으로 쌓이고, 관측 엣지의 빈 자리를 메우는 일은
// 조회할 때 화면에서 일어난다 — 적재가 관측을 고치면 collector의 서명과 어긋나고, 원본에서
// 다시 계산할 때 저장된 값과 달라진다.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/declaration"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	out := flag.String("out", "./declared-attribution", "directory to write the declared-lane result into")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pqcota-declare-attribution [--out <dir>] <attribution.csv>")
		fmt.Fprintln(os.Stderr, "  CSV: node_id,dst,app_key")
		os.Exit(2)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot open the input:", err)
		os.Exit(1)
	}
	defer f.Close()

	results, err := declaration.ImportAttributionCSV(f)
	if err != nil {
		// 어느 엣지를 가리키는지 모르는 줄은 추측하지 않고 멈춘다 — 앱을 잘못 짚으면
		// 조치 대상이 바뀐다.
		fmt.Fprintln(os.Stderr, "cannot read the declarations:", err)
		os.Exit(1)
	}
	if len(results) == 0 {
		fmt.Fprintln(os.Stderr, "no declarations at all — the CSV is empty or header-only.")
		os.Exit(1)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	enc := protojson.MarshalOptions{Multiline: true, Indent: "  "}
	total := 0
	for i, res := range results {
		b, err := enc.Marshal(res)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal:", err)
			os.Exit(1)
		}
		p := filepath.Join(*out, fmt.Sprintf("attribution-%03d.json", i))
		if err := os.WriteFile(p, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		total += len(res.GetObservedEdges())
	}

	fmt.Printf("%d apps declared by a person (%d nodes) → %s\n", total, len(results), *out)
	fmt.Println("this is **not an observation** — it accumulates in the declared lane with detection_method=UNSPECIFIED.")
	fmt.Println("apps already attributed by observation are not overwritten; only the blanks are filled at view time.")
	fmt.Printf("next: pqcota-ingest %s\n", *out)
}
