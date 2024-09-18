package waceWAF

import (
	"fmt"
	"io"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"
)

type WaceWAF struct {
	coraza.WAF
	waceConfig *WaceConfig
}

type WaceTransaction struct {
	types.Transaction
	waf             *WaceWAF
	requestLine     *string
	requestHeaders  *string
	requestBody     *string
	responseLine    *string
	responseHeaders *string
	responseBody    *string
}

// TODO: Parametrize the path to the waceconfig.yaml file
func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {
	wace.Init("../Pruebas/ModSecIntl_wace_core/waceconfig.yaml")
	waceConfig := NewWaceConfig()
	waf, err := coraza.NewWAF(config.
		WithDirectives("SecRuleUpdateActionById 949110 pass").
		WithDirectives("SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, deny, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation', tag:'OWASP_CRS', ver:'OWASP_CRS/4.4.0-dev'\"").
		WithDirectives("SecRuleUpdateActionById 959100 pass").
		WithDirectives("SecRule TX:BLOCKING_OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_threshold}\" \"id:959102, phase:4, deny, t:none, msg:'%{TX.BLOCKING_OUTBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation', tag:'OWASP_CRS', ver:'OWASP_CRS/4.4.0-dev'\""))
	return &WaceWAF{waf, waceConfig}, err
}

// Implements the NewTransaction interfaces provided by Coraza WAF to return a new WaceTransaction transaction
// TODO: Delete the debug prints
func (w *WaceWAF) NewTransaction() types.Transaction {
	fmt.Println("[DEBUG][WACE] New wace-Coraza transaction")

	return WaceTransaction{w.WAF.NewTransaction(), w, new(string), new(string), new(string), new(string), new(string), new(string)}
}

func (t WaceTransaction) ProcessURI(uri string, method string, httpVersion string){
	t.Transaction.ProcessURI(uri, method, httpVersion)
	*t.requestLine = method + " " + uri + " " + httpVersion
}

// TODO: Analyze if the interface SetServerName of the transaction should be implemented
func (t WaceTransaction) SetServerName(serverName string) {
	t.Transaction.SetServerName(serverName)
	*t.requestHeaders += "Server: " + serverName + "\n"
}

// TODO: Check how the headers are appended to the variable
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	t.Transaction.AddRequestHeader(key, value)
	*t.requestHeaders += key + ": " + value + "\n"
}

// Implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
// TODO: Add early check for phase 1
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	go func() {
		fmt.Println("[DEBUG][WACE] Processing request headers by WACE and Coraza")
		wace.AnalyzeReqLineAndHeaders(t.Transaction.ID(), *t.requestLine, *t.requestHeaders, t.waf.waceConfig.reqHeadModelIDs)
	}()

	interruption := t.Transaction.ProcessRequestHeaders()

	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error){
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	*t.requestBody = string(b)
	return t.Transaction.ReadRequestBodyFrom(r)
}


// Implements the ProcessRequestBody interface provided by Coraza WAF to process request body by WACE and Coraza
func (t WaceTransaction) ProcessRequestBody() (*types.Interruption, error) {
	go func() {
		fmt.Println("[DEBUG][WACE] Processing request body by WACE and Coraza")
		wace.AnalyzeRequestBody(t.Transaction.ID(), *t.requestBody, t.waf.waceConfig.reqBodyModelIDs)
	}()
	go func() {
		fmt.Println("[DEBUG][WACE] Processing request by WACE and Coraza")
		wace.AnalyzeRequest(t.Transaction.ID(), *t.requestLine+"\n"+ *t.requestHeaders+"\n"+ *t.requestBody, t.waf.waceConfig.reqBodyModelIDs)
	}()
	interruption, err := t.Transaction.ProcessRequestBody()

	mtRules := t.MatchedRules()

	mtRulesLen := len(mtRules)

	// TODO: Get and parse threshold with a new rule
	wafParams := map[string]string{"anomalyscore": mtRules[mtRulesLen-1].Message(), "inboundthreshold": "8"}

	// TODO: Get decision plugin id from the configstore
	result, err := wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

	if err == nil {
		if result {
			fmt.Println("[DEBUG][WACE] Transaction blocked")
			interruption = &types.Interruption{Action: "deny"}
		}
	}

	return interruption, err
}

func (t WaceTransaction) AddResponseHeader(key string, value string) {
	t.Transaction.AddResponseHeader(key, value)
	*t.responseHeaders += key + ": " + value + "\n"
}

// Implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
// TODO: Check for a better function to parse status code
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	*t.responseLine = proto + " " + fmt.Sprint(code)
	interruption := t.Transaction.ProcessResponseHeaders(code, proto)
	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) WriteResponseBody(b []byte) (*types.Interruption, int, error){
	*t.responseBody = string(b)
	return t.Transaction.WriteResponseBody(b)
}

// Implements the ProcessResponseBody interface provided by Coraza WAF to process response body by WACE and Coraza
func (t WaceTransaction) ProcessResponseBody() (*types.Interruption, error) {
	interruption, err := t.Transaction.ProcessResponseBody()
	return interruption, err
}

func (t WaceTransaction) ProcessLogging() {
	t.Transaction.ProcessLogging()
}
