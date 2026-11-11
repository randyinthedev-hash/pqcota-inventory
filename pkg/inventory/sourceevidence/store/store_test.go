// SPDX-FileCopyrightText: 2026 Great Honor <randyinthedev@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence"
	"github.com/randyinthedev-hash/pqcota-inventory/pkg/inventory/sourceevidence/store"
)

var (
	_ store.Store = (*store.MemStore)(nil)
	_ store.Store = (*store.PgStore)(nil)
)

// cbom — 실행마다 다른 바이트가 되도록 serialNumber에 표시를 넣는다(Pg는 append-only라 지우지 않는다).
func cbom(mark string) []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:` + mark + `",
 "metadata":{"tools":{"components":[{"type":"application","name":"scanner","version":"1.0"}]}},
 "components":[
  {"type":"cryptographic-asset","bom-ref":"rsa","name":"RSA",
   "cryptoProperties":{"assetType":"algorithm","algorithmProperties":{"primitive":"pke"}},
   "evidence":{"occurrences":[{"location":"src/Wrap.cs","line":12,"offset":5},{"location":"src/Wrap.cs","line":30}]}},
  {"type":"library","name":"not-crypto"}
 ]}`)
}

func convert(t *testing.T, raw []byte) *sourceevidence.Interpretation {
	t.Helper()
	in, err := sourceevidence.Convert(raw, sourceevidence.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// suite — 두 구현이 같은 규칙을 지키는지 본다. open은 조직마다 새 핸들을 준다.
func suite(t *testing.T, open func(t *testing.T, organization string) store.Store) {
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)

	t.Run("save, read back, receive again", func(t *testing.T) {
		s := open(t, "org-a-"+stamp)
		raw := cbom("a-" + stamp)
		interp := convert(t, raw)

		r1, err := s.Save(store.Input{NodeID: "web-01", Raw: raw}, interp)
		if err != nil {
			t.Fatal(err)
		}
		if !r1.NewInput || !r1.NewInterpretation || r1.InterpretationID != interp.ID {
			t.Fatalf("first receipt %+v", r1)
		}
		// 같은 것을 다시 받으면 내용은 그대로이고 수신 기록만 는다.
		r2, err := s.Save(store.Input{NodeID: "web-02", Raw: raw}, convert(t, raw))
		if err != nil {
			t.Fatal(err)
		}
		if r2.NewInput || r2.NewInterpretation || r2.Seq <= r1.Seq || r2.NodeID != "web-02" {
			t.Fatalf("second receipt %+v (first %+v)", r2, r1)
		}

		got, err := s.Interpretation(interp.ID)
		if err != nil || got == nil {
			t.Fatalf("Interpretation: %v %v", got, err)
		}
		if !bytes.Equal(marshal(t, got), marshal(t, interp)) {
			t.Fatalf("stored interpretation differs from what was saved")
		}
		if b, err := s.InputRaw(interp.InputSHA256); err != nil || !bytes.Equal(b, raw) {
			t.Fatalf("InputRaw: %v, equal=%v", err, bytes.Equal(b, raw))
		}

		list, err := s.Interpretations(0)
		if err != nil || len(list) != 1 {
			t.Fatalf("Interpretations: %d %v", len(list), err)
		}
		if l := list[0]; l.ID != interp.ID || l.SpecVersion != "1.6" || l.Counts.Components != 1 || l.Counts.OutOfScope != 1 ||
			l.Counts.Locations != 2 || len(l.Rules) != 1 || len(l.Producer) == 0 || l.CreatedAt.IsZero() {
			t.Fatalf("summary %+v", l)
		}
		rc, err := s.Receipts(0)
		if err != nil || len(rc) != 2 || rc[0].Seq != r2.Seq || rc[1].Seq != r1.Seq {
			t.Fatalf("Receipts: %+v %v", rc, err)
		}
		if ro, err := s.ReceiptsOf(interp.ID, 0); err != nil || len(ro) != 2 || ro[0].NodeID != "web-02" || ro[1].NodeID != "web-01" {
			t.Fatalf("ReceiptsOf: %+v %v", ro, err)
		}
		if ro, err := s.ReceiptsOf(interp.ID, 1); err != nil || len(ro) != 1 || ro[0].Seq != r2.Seq {
			t.Fatalf("ReceiptsOf limit 1: %+v %v", ro, err)
		}
		if ro, _ := s.ReceiptsOf("no-such-id", 0); len(ro) != 0 {
			t.Fatalf("ReceiptsOf of an unknown id: %+v", ro)
		}
	})

	t.Run("same id, different content is refused and leaves nothing", func(t *testing.T) {
		s := open(t, "org-imm-"+stamp)
		raw := cbom("imm-" + stamp)
		interp := convert(t, raw)
		if _, err := s.Save(store.Input{Raw: raw}, interp); err != nil {
			t.Fatal(err)
		}
		// ID는 항목을 보지 않는다 — 같은 판의 변환기가 다른 항목을 낸 꼴이다.
		changed := convert(t, raw)
		changed.Items[0].Reported = append(changed.Items[0].Reported, sourceevidence.Field{Name: "x", Value: "y", Pointer: "/x"})
		if _, err := s.Save(store.Input{Raw: raw}, changed); !errors.Is(err, store.ErrImmutable) {
			t.Fatalf("want ErrImmutable, got %v", err)
		}
		if rc, _ := s.Receipts(0); len(rc) != 1 {
			t.Fatalf("a refused save left a receipt: %d", len(rc))
		}
		got, _ := s.Interpretation(interp.ID)
		if got == nil || !bytes.Equal(marshal(t, got), marshal(t, interp)) {
			t.Fatalf("the stored interpretation changed")
		}
	})

	t.Run("mismatched input or id is refused before writing", func(t *testing.T) {
		s := open(t, "org-mis-"+stamp)
		raw := cbom("mis-" + stamp)
		interp := convert(t, raw)
		if _, err := s.Save(store.Input{Raw: append([]byte(" "), raw...)}, interp); !errors.Is(err, store.ErrMismatch) {
			t.Fatalf("other bytes: want ErrMismatch, got %v", err)
		}
		bad := convert(t, raw)
		bad.ExcludedRuleIDs = []string{"standard-occurrences"} // ID를 다시 계산하지 않았다
		if _, err := s.Save(store.Input{Raw: raw}, bad); !errors.Is(err, store.ErrMismatch) {
			t.Fatalf("stale id: want ErrMismatch, got %v", err)
		}
		if _, err := s.Save(store.Input{Raw: raw}, nil); !errors.Is(err, store.ErrMismatch) {
			t.Fatalf("nil: want ErrMismatch, got %v", err)
		}
		list, _ := s.Interpretations(0)
		rc, _ := s.Receipts(0)
		b, _ := s.InputRaw(interp.InputSHA256)
		if len(list) != 0 || len(rc) != 0 || b != nil {
			t.Fatalf("refused saves left data: %d interpretations, %d receipts, input=%v", len(list), len(rc), b != nil)
		}
	})

	t.Run("organizations do not see each other", func(t *testing.T) {
		a, b := open(t, "org-x-"+stamp), open(t, "org-y-"+stamp)
		raw := cbom("iso-" + stamp)
		interp := convert(t, raw)
		if _, err := a.Save(store.Input{NodeID: "web-01", Raw: raw}, interp); err != nil {
			t.Fatal(err)
		}
		if got, err := b.Interpretation(interp.ID); err != nil || got != nil {
			t.Fatalf("Interpretation opens another organization's result by id: %v %v", got, err)
		}
		if got, err := b.InputRaw(interp.InputSHA256); err != nil || got != nil {
			t.Fatalf("InputRaw opens another organization's input by hash: %v", err)
		}
		if l, _ := b.Interpretations(0); len(l) != 0 {
			t.Fatalf("Interpretations leaks: %d", len(l))
		}
		if rc, _ := b.Receipts(0); len(rc) != 0 {
			t.Fatalf("Receipts leaks: %d", len(rc))
		}
		if rc, _ := b.ReceiptsOf(interp.ID, 0); len(rc) != 0 {
			t.Fatalf("ReceiptsOf leaks: %d", len(rc))
		}
		// 같은 바이트를 다른 조직이 받으면 그 조직에서는 새 것이다.
		r, err := b.Save(store.Input{Raw: raw}, convert(t, raw))
		if err != nil || !r.NewInput || !r.NewInterpretation {
			t.Fatalf("same bytes in another organization: %+v %v", r, err)
		}
	})

	t.Run("the same new input arriving at once is stored once", func(t *testing.T) {
		s := open(t, "org-race-"+stamp)
		raw := cbom("race-" + stamp)
		const n = 8
		var wg sync.WaitGroup
		rs := make([]store.Receipt, n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				in, err := sourceevidence.Convert(raw, sourceevidence.DefaultLimits)
				if err != nil {
					errs[i] = err
					return
				}
				rs[i], errs[i] = s.Save(store.Input{NodeID: "n" + strconv.Itoa(i), Raw: raw}, in)
			}(i)
		}
		wg.Wait()
		newIn, newInterp := 0, 0
		for i := range rs {
			if errs[i] != nil {
				t.Fatalf("save %d: %v", i, errs[i])
			}
			if rs[i].NewInput {
				newIn++
			}
			if rs[i].NewInterpretation {
				newInterp++
			}
		}
		if newIn != 1 || newInterp != 1 {
			t.Fatalf("new input %d, new interpretation %d; want 1 and 1", newIn, newInterp)
		}
		if rc, _ := s.Receipts(0); len(rc) != n {
			t.Fatalf("receipts %d, want %d", len(rc), n)
		}
		if l, _ := s.Interpretations(0); len(l) != 1 {
			t.Fatalf("interpretations %d, want 1", len(l))
		}
	})

	t.Run("changing what was passed in or handed out does not change what is stored", func(t *testing.T) {
		s := open(t, "org-alias-"+stamp)
		raw := cbom("alias-" + stamp)
		interp := convert(t, raw)
		want := marshal(t, interp)
		if _, err := s.Save(store.Input{Raw: raw}, interp); err != nil {
			t.Fatal(err)
		}
		// 저장에 넘긴 값을 고친다.
		raw[0] = ' '
		interp.Rules[0].ID = "changed"
		interp.Producer[0].Value = "changed"
		interp.Counts.Diagnostics["changed"] = 1
		interp.Items[0].Reported[0].Value = "changed"

		// 받아 간 값을 고친다.
		l, _ := s.Interpretations(0)
		l[0].Rules[0].ID = "changed"
		l[0].Producer[0].Value = "changed"
		if l[0].Counts.Diagnostics == nil {
			l[0].Counts.Diagnostics = map[string]int{}
		}
		l[0].Counts.Diagnostics["changed"] = 1
		got, _ := s.Interpretation(interp.ID)
		got.Rules[0].ID = "changed"
		got.Items[0].Reported[0].Value = "changed"
		b, _ := s.InputRaw(convert(t, cbom("alias-"+stamp)).InputSHA256)
		b[0] = 'x'

		// 다시 읽으면 처음 저장한 그대로이고, 목록과 상세가 같은 값을 말한다.
		got, _ = s.Interpretation(interp.ID)
		if !bytes.Equal(marshal(t, got), want) {
			t.Fatalf("detail changed after the caller edited values")
		}
		l, _ = s.Interpretations(0)
		if l[0].Rules[0].ID != got.Rules[0].ID || l[0].Producer[0].Value != got.Producer[0].Value ||
			!bytes.Equal(marshal(t, l[0].Counts), marshal(t, got.Counts)) {
			t.Fatalf("list and detail disagree: %+v vs rules %+v counts %+v", l[0], got.Rules, got.Counts)
		}
		if rb, _ := s.InputRaw(got.InputSHA256); !bytes.Equal(rb, cbom("alias-"+stamp)) {
			t.Fatalf("stored input changed")
		}
	})

	t.Run("newest first and limit", func(t *testing.T) {
		s := open(t, "org-ord-"+stamp)
		var ids []string
		for i := 0; i < 3; i++ {
			raw := cbom("ord-" + strconv.Itoa(i) + "-" + stamp)
			in := convert(t, raw)
			if _, err := s.Save(store.Input{Raw: raw}, in); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, in.ID)
		}
		l, err := s.Interpretations(2)
		if err != nil || len(l) != 2 || l[0].ID != ids[2] || l[1].ID != ids[1] {
			t.Fatalf("order: %v %v", l, err)
		}
		if got, _ := s.Interpretation("no-such-id"); got != nil {
			t.Fatalf("missing id returned a result")
		}
	})
}

func TestMemStore(t *testing.T) {
	suite(t, func(t *testing.T, o string) store.Store {
		s, err := store.NewMemStoreIn(o)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// TestPgStore — 격리·트랜잭션의 실제 시험은 여기다. PQCOTA_TEST_DSN이 있을 때만 돈다. 스킵은 통과가 아니다.
func TestPgStore(t *testing.T) {
	dsn := os.Getenv("PQCOTA_TEST_DSN")
	if dsn == "" {
		t.Skip("PQCOTA_TEST_DSN is not set — skipping the Postgres integration test")
	}
	suite(t, func(t *testing.T, o string) store.Store {
		s, err := store.NewPgStoreIn(context.Background(), dsn, o)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	})
}
