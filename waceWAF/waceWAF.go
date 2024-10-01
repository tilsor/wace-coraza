package waceWAF

import (
	"fmt"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"
)

type WaceWAF struct {
	coraza.WAF
	exceptionWAF  coraza.WAF
	waceConfig    *WaceConfig
	earlyBlocking bool
}

type WaceTransaction struct {
	types.Transaction
	exceptionTransaction types.Transaction
	waf                  *WaceWAF
	requestLine          *string
	requestHeaders       *string
	requestBody          *string
	responseLine         *string
	responseHeaders      *string
	responseBody         *string
}

// TODO: Parametrize the path to the waceconfig.yaml file
func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {

	wafConfigs, ok := config.(*waceWAFConfig)

	wafConfigs.LoadConfig("/mnt/c/Users/agust/Desktop/ProyGrado/Pruebas/ModSecIntl_wace_core/waceconfig.yaml")

	wace.Init()

	if !ok {
		return nil, fmt.Errorf("Error casting to waceWAFConfig")
	}

	// Get rules by CRS Version
	configRules := wafConfigs.getConfigRules(wafConfigs.options["crs_version"])

	for _, rule := range configRules {
		wafConfigs.WAFConfig = wafConfigs.WAFConfig.WithDirectives(rule)
	}

	waf, err := coraza.NewWAF(wafConfigs.WAFConfig)

	waceConfig := NewWaceConfig()

	if wafConfigs.wantExceptions {
		wafConfigs.exceptionsConfig = wafConfigs.LoadExceptionsDirectives("exceptions.conf", waceConfig)
	}

	exceptionsWaf, err := coraza.NewWAF(wafConfigs.exceptionsConfig)

	return &WaceWAF{waf, exceptionsWaf, waceConfig, wafConfigs.options["early_blocking"] == "true"}, err
}

// Implements the NewTransaction interfaces provided by Coraza WAF to return a new WaceTransaction transaction
// TODO: Delete the debug prints
func (w *WaceWAF) NewTransaction() types.Transaction {
	fmt.Println("[DEBUG][WACE] New wace-Coraza transaction")

	return WaceTransaction{w.WAF.NewTransaction(), w.exceptionWAF.NewTransaction(), w, new(string), new(string), new(string), new(string), new(string), new(string)}
}

func (t WaceTransaction) ProcessURI(uri string, method string, httpVersion string) {
	t.Transaction.ProcessURI(uri, method, httpVersion)
	t.exceptionTransaction.ProcessURI(uri, method, httpVersion)
	*t.requestLine = method + " " + uri + " " + httpVersion
}

// TODO: Analyze if the interface SetServerName of the transaction should be implemented
func (t WaceTransaction) SetServerName(serverName string) {
	t.Transaction.SetServerName(serverName)
	t.exceptionTransaction.SetServerName(serverName)
	*t.requestHeaders += "Server: " + serverName + "\n"
}

// TODO: Check how the headers are appended to the variable
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	t.Transaction.AddRequestHeader(key, value)
	t.exceptionTransaction.AddRequestHeader(key, value)
	*t.requestHeaders += key + ": " + value + "\n"
}

// Implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
// TODO: Add early check for phase 1
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	go func() {
		fmt.Println("[DEBUG][WACE] Processing request headers by WACE and Coraza")
		t.exceptionTransaction.ProcessRequestHeaders()

		activeModels := []string{}
		requestHeadersExceptionRuleMessage := ""
		i := len(t.exceptionTransaction.MatchedRules()) - 1
		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 100 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 100 {
			requestHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeModels = ParseActiveModels(requestHeadersExceptionRuleMessage)

			for _, model := range activeModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}
		wace.AnalyzeReqLineAndHeaders(t.Transaction.ID(), *t.requestLine, *t.requestHeaders, activeModels)
	}()

	interruption := t.Transaction.ProcessRequestHeaders()

	if t.waf.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "1"

		wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)
	}

	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	*t.requestBody = string(b)

	interruption, cantB, err := t.exceptionTransaction.ReadRequestBodyFrom(r)

	if err != nil {
		return interruption, 0, err
	}

	interruption, cantB, err = t.Transaction.ReadRequestBodyFrom(r)

	return interruption, cantB, err
}

// Implements the ProcessRequestBody interface provided by Coraza WAF to process request body by WACE and Coraza
func (t WaceTransaction) ProcessRequestBody() (*types.Interruption, error) {
	go func() {
		t.exceptionTransaction.ProcessRequestBody()

		requestBodyExceptionRuleMessage := ""
		requestExceptionRuleMessage := ""
		activeRequestBodyModels := []string{}
		activeRequestModels := []string{}

		i := len(t.exceptionTransaction.MatchedRules()) - 1
		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 300 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 300 {
			requestExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeRequestModels := ParseActiveModels(requestExceptionRuleMessage)
			for _, model := range activeRequestModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}

		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 200 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 200 {
			requestBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeRequestBodyModels := ParseActiveModels(requestBodyExceptionRuleMessage)
			for _, model := range activeRequestBodyModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}
		go func() {
			fmt.Println("[DEBUG][WACE] Processing request body by WACE and Coraza")
			wace.AnalyzeRequestBody(t.Transaction.ID(), *t.requestBody, activeRequestBodyModels)
		}()
		go func() {
			fmt.Println("[DEBUG][WACE] Processing request by WACE and Coraza")
			wace.AnalyzeRequest(t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders+"\n"+*t.requestBody, activeRequestModels)
		}()
	}()

	interruption, err := t.Transaction.ProcessRequestBody()

	if err != nil {
		fmt.Println("[DEBUG][WACE] Error processing request body by Coraza: " + err.Error())
	}

	mtRules := t.MatchedRules()

	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "2"

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
	t.exceptionTransaction.AddResponseHeader(key, value)
	*t.responseHeaders += key + ": " + value + "\n"
}

// Implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
// TODO: Check for a better function to parse status code
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	*t.responseLine = proto + " " + fmt.Sprint(code)
	go func() {
		fmt.Println("[DEBUG][WACE] Processing response headers by WACE and Coraza")
		t.exceptionTransaction.ProcessResponseHeaders(code, proto)

		responseHeadersExceptionRuleMessage := ""
		activeModels := []string{}

		i := len(t.exceptionTransaction.MatchedRules()) - 1
		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 400 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 400 {
			responseHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeModels = ParseActiveModels(responseHeadersExceptionRuleMessage)

			for _, model := range activeModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}
		wace.AnalyzeRespLineAndHeaders(t.Transaction.ID(), *t.responseLine, *t.responseHeaders, activeModels)
	}()

	interruption := t.Transaction.ProcessResponseHeaders(code, proto)

	if t.waf.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "3"

		wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)
	}

	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	*t.responseBody = string(b)

	interruption, cantB, err := t.exceptionTransaction.WriteResponseBody(b)

	if err != nil {
		return interruption, 0, err
	}

	interruption, cantB, err = t.Transaction.WriteResponseBody(b)

	return interruption, cantB, err
}

// Implements the ProcessResponseBody interface provided by Coraza WAF to process response body by WACE and Coraza
func (t WaceTransaction) ProcessResponseBody() (*types.Interruption, error) {
	go func() {
		t.exceptionTransaction.ProcessResponseBody()
		responseBodyExceptionRuleMessage := ""
		responseExceptionRuleMessage := ""
		activeResponseBodyModels := []string{}
		activeResponseModels := []string{}

		i := len(t.exceptionTransaction.MatchedRules()) - 1
		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 600 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 600 {
			responseExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeResponseModels := ParseActiveModels(responseExceptionRuleMessage)
			for _, model := range activeResponseModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}

		for t.exceptionTransaction.MatchedRules()[i].Rule().ID() != 500 {
			i--
		}
		if t.exceptionTransaction.MatchedRules()[i].Rule().ID() == 500 {
			responseBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
			activeResponseBodyModels := ParseActiveModels(responseBodyExceptionRuleMessage)
			for _, model := range activeResponseBodyModels {
				fmt.Println("[DEBUG][WACE] Active model: ", model)
			}
		}

		go func() {
			fmt.Println("[DEBUG][WACE] Processing response body by WACE and Coraza")
			wace.AnalyzeResponseBody(t.Transaction.ID(), *t.responseBody, activeResponseBodyModels)
		}()
		go func() {
			fmt.Println("[DEBUG][WACE] Processing response by WACE and Coraza")
			wace.AnalyzeResponse(t.Transaction.ID(), *t.responseLine+"\n"+*t.responseHeaders+"\n"+*t.responseBody, activeResponseModels)
		}()
	}()

	interruption, err := t.Transaction.ProcessResponseBody()

	mtRules := t.MatchedRules()
	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "4"

	wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

	return interruption, err
}

func (t WaceTransaction) ProcessLogging() {
	t.Transaction.ProcessLogging()
}
