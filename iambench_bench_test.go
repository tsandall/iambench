package iambench

import (
	"context"
	"fmt"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// goos: linux
// goarch: amd64
// pkg: github.com/open-policy-agent/iambench
// BenchmarkIteration/30-8         	    2000	    556898 ns/op
// BenchmarkIteration/300-8        	     300	   5414427 ns/op
// BenchmarkIteration/3000-8       	      20	  58559553 ns/op
// BenchmarkIteration/30000-8      	       2	 691029210 ns/op
// PASS
// ok  	github.com/open-policy-agent/iambench	8.324s
func BenchmarkIteration(b *testing.B) {
	ctx := context.Background()
	sizes := []int{30, 300, 3000, 30000}
	for _, n := range sizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {

			store := inmem.NewFromObject(CreateExactACPs(n))

			pq, err := rego.New(
				rego.Query("data.test.allow"),
				rego.Module("test.rego", `
					package test

					allow {
						data.store.ory.exact.policies[_].resources[_] = _
					}`),
				rego.Store(store)).PrepareForEval(ctx)

			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				rs, err := pq.Eval(ctx)
				if err != nil {
					b.Fatal(err)
				} else if len(rs) == 0 {
					b.Fatal("Undefined result")
				}
			}
		})
	}
}

// goos: linux
// goarch: amd64
// pkg: github.com/tsandall/iambench
// BenchmarkPartialEvalExact/30-8         	     100	  17083933 ns/op	 4096193 B/op	  129728 allocs/op
// BenchmarkPartialEvalExact/300-8        	      10	 187831481 ns/op	40239613 B/op	 1279931 allocs/op
// BenchmarkPartialEvalExact/3000-8       	       1	1964790773 ns/op	401378792 B/op	12782005 allocs/op
// BenchmarkPartialEvalExact/30000-8      	       1	18977663120 ns/op	4016005552 B/op	127802102 allocs/op
// PASS
// ok  	github.com/tsandall/iambench	25.222s
func BenchmarkPartialEvalExact(b *testing.B) {
	ctx := context.Background()
	sizes := []int{30, 300, 3000, 30000}
	for _, n := range sizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {

			store := inmem.NewFromObject(CreateExactACPs(n))

			r, err := rego.New(
				rego.Query("data.ory.exact.allow = true"),
				rego.Module("test.rego", ExactPolicy),
				rego.Store(store),
				rego.DisableInlining([]string{
					"data.ory.exact.any_allow",
					"data.ory.exact.any_deny",
				}),
			).PrepareForPartial(ctx)
			if err != nil {
				b.Fatal(err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {

				pq, err := r.Partial(ctx)
				if err != nil {
					b.Fatal(err)
				}

				exp := n * 8

				if len(pq.Queries) != 1 {
					b.Fatal("Expected exactly one query")
				} else if len(pq.Support) != 1 {
					b.Fatal("Expected exactly one support module")
				} else if len(pq.Support[0].Rules) != exp {
					b.Fatalf("Expected exactly %d support rules", exp)
				}
			}
		})
	}
}

func BenchmarkEvalExact(b *testing.B) {
	ctx := context.Background()
	sizes := []int{30, 300, 3000} // 30000
	for _, n := range sizes {
		b.Run(fmt.Sprint(n), func(b *testing.B) {

			store := inmem.NewFromObject(CreateExactACPs(n))

			prepared, err := rego.New(
				rego.Query("data.ory.exact.allow"),
				rego.Module("test.rego", ExactPolicy),
				rego.Store(store),
				rego.DisableInlining([]string{
					"data.ory.exact.any_allow",
					"data.ory.exact.any_deny",
				}),
			).PrepareForEval(ctx, rego.WithPartialEval())
			if err != nil {
				b.Fatal(err)
			}

			input := &Input{
				Subject:  "tenant:acmecorp:user:user.name@domain.com",
				Action:   "check",
				Resource: "tenant:acmecorp:thing0:resource-dead-beef-feed-face",
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				rs, err := prepared.Eval(ctx, rego.EvalInput(input))
				if err != nil {
					b.Fatal(err)
				} else if len(rs) != 1 || rs[0].Expressions[0].Value.(bool) {
					b.Fatalf("Expected denied but got %v", rs)
				}
			}
		})
	}
}

func TestEvalExact(t *testing.T) {
	ctx := context.Background()
	store := inmem.NewFromObject(CreateExactACPs(30))
	prepared, err := rego.New(
		rego.Query("data.ory.exact.allow"),
		rego.Module("test.rego", ExactPolicy),
		rego.Store(store),
		rego.DisableInlining([]string{
			"data.ory.exact.any_allow",
			"data.ory.exact.any_deny",
		}),
	).PrepareForEval(ctx, rego.WithPartialEval())
	if err != nil {
		t.Fatal(err)
	}

	denied := &Input{
		Subject:  "tenant:acmecorp:user:user.name@domain.com",
		Action:   "check",
		Resource: "tenant:acmecorp:thing0:resource-dead-beef-feed-face",
	}

	allowed := &Input{
		Subject:  "tenant:acmecorp:user:user.name@domain.com",
		Resource: "tenant:acmecorp:thing0:resource-1111-2222-3333-4444",
		Action:   "check",
	}

	rs, err := prepared.Eval(ctx, rego.EvalInput(denied))
	if err != nil {
		t.Fatal(err)
	} else if len(rs) != 1 || rs[0].Expressions[0].Value.(bool) {
		t.Fatalf("Expected denied but got %v", rs)
	}

	rs, err = prepared.Eval(ctx, rego.EvalInput(allowed))
	if err != nil {
		t.Fatal(err)
	} else if len(rs) != 1 || !rs[0].Expressions[0].Value.(bool) {
		t.Fatalf("Expected allowed but got %v", rs)
	}
}
