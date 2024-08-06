package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	waceWAF "gitlab.fing.edu.uy/gsi/pgrado-wace/poc/waceWAF"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func exampleHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	resBody := "Hello world, transaction not disrupted."

	if body := os.Getenv("RESPONSE_BODY"); body != "" {
		resBody = body
	}

	if h := os.Getenv("RESPONSE_HEADERS"); h != "" {
		key, val, _ := strings.Cut(h, ":")
		w.Header().Set(key, val)
	}

	// The server generates the response
	w.Write([]byte(resBody))
}

func main() {
	waf := createWAF()

	http.Handle("/", txhttp.WrapHandler(waf, http.HandlerFunc(exampleHandler)))

	fmt.Println("Server is running. Listening port: 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {
	cfg := coraza.NewWAFConfig().
		WithDirectivesFromFile("coraza.conf").
		WithDirectivesFromFile("coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("coreruleset/rules/*.conf").
		WithDirectives("SecRuleRemoveById 949110").
		WithDirectives("SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, deny, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation', tag:'OWASP_CRS', ver:'OWASP_CRS/4.4.0-dev'\"")
	waf, err := waceWAF.NewWAF(cfg)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}
