package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"time"

	"github.com/open-policy-agent/opa/metrics"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/tsandall/iambench"
)

var flavor = flag.String("flavor", "exact", "set policy flavor to use (options: exact, glob)")
var amount = flag.Int("amount", 30000, "set number of ACPs to generate")
var instrument = flag.Bool("instrument", false, "enable OPA instrumentation")

type prepareParams struct {
	GetStore        func() storage.Store
	DisableInlining []string
	Query           string
	Policy          string
}

func main() {

	flag.Parse()

	ctx := context.Background()

	var prepared rego.PreparedEvalQuery

	switch *flavor {
	case "exact":
		prepared = prepareQuery(ctx, prepareParams{
			GetStore: func() storage.Store {
				return inmem.NewFromObject(iambench.CreateExactACPs(*amount))
			},
			Query: "data.ory.exact.allow",
			DisableInlining: []string{
				"data.ory.exact.any_allow",
				"data.ory.exact.any_deny",
			},
			Policy: iambench.ExactPolicy,
		})
	case "flavor":
		prepared = prepareQuery(ctx, prepareParams{
			GetStore: func() storage.Store {
				return inmem.NewFromObject(iambench.CreateGlobACPs(*amount))
			},
			DisableInlining: []string{
				"data.ory.glob.any_allow",
				"data.ory.glob.any_deny",
			},
			Query:  "data.ory.glob.allow",
			Policy: iambench.GlobPolicy,
		})
	default:
		log.Fatal("invalid value")
	}

	input := &iambench.Input{
		Subject:  "tenant:acmecorp:user:user.name@domain.com",
		Action:   "check",
		Resource: "tenant:acmecorp:thing0:resource-dead-beef-feed-face",
	}

	m := metrics.New()
	tprint := time.Now()
	log.Println("Running evaluation...")
	log.Printf("%-20v %-20v %-20v %-20v", "mean", "90%", "99%", "99.9%")

	for {

		tnow := time.Now()

		if time.Since(tprint) > (5 * time.Second) {
			tprint = tnow
			hist := m.Histogram("eval_ns").Value().(map[string]interface{})
			m.Clear()
			log.Printf("%-20v %-20v %-20v %-20v", ifloat2duration(hist["mean"]), ifloat2duration(hist["90%"]), ifloat2duration(hist["99%"]), ifloat2duration(hist["99.9%"]))
		}

		rs, err := prepared.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			log.Fatal(err)
		} else if len(rs) != 1 || rs[0].Expressions[0].Value.(bool) {
			log.Fatal("Expected deny")
		}

		m.Histogram("eval_ns").Update(int64(time.Since(tnow)))
	}

}

func prepareQuery(ctx context.Context, params prepareParams) rego.PreparedEvalQuery {

	log.Println("Running partial evaluation...")

	m := metrics.New()
	prepared, err := rego.New(
		rego.Instrument(*instrument),
		rego.Query(params.Query),
		rego.Module("test.rego", params.Policy),
		rego.Store(params.GetStore()),
		rego.DisableInlining(params.DisableInlining),
		rego.Metrics(m),
	).PrepareForEval(ctx, rego.WithPartialEval())
	if err != nil {
		log.Fatal(err)
	}

	bs, _ := json.MarshalIndent(m, "", "  ")
	log.Println("Partial evaluation metrics:", string(bs))

	return prepared
}

func ifloat2duration(i interface{}) time.Duration {
	return time.Duration(i.(float64))
}
