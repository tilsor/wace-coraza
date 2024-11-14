package waceWAF

// import (
// 	// "strings"
// 	// "testing"
// )

// func TestProcessURI(t *testing.T) {
// 	wafConfig := waceWAFConfig{
// 		WAFConfig: NewWAFConfig(),
// 		exceptionsConfig: NewWAFConfig(),
// 		waceAppConfigFilePath: "waceconfig.yaml",
// 		exceptionsFilePath: "waceexceptions.conf",
// 		waceDecisionId: "waceDecisionId",
// 		earlyBlocking: false,
// 	}
// 	waf, err := NewWAF(&wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedRequestLine := "GET http://localhost:8090 HTTP/1.1"
// 	gotRequestLine := *txW.requestLine
// 	if expectedRequestLine != gotRequestLine {
// 		t.Errorf("Error processing URI: Expected: %s, Got: %s", expectedRequestLine, gotRequestLine)
// 	}
// }

// func TestAddRequestHeader(t *testing.T) {
// 	wafConfig := NewWAFConfig()
// 	wafConfig = wafConfig
// 	waf, err := NewWAF(wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedRequestHeaders := "content-type: application/x-www-form-urlencoded\n"
// 	gotRequestHeaders := *txW.requestHeaders
// 	if expectedRequestHeaders != gotRequestHeaders {
// 		t.Errorf("Error adding request header: Expected: %s, Got: %s", expectedRequestHeaders, gotRequestHeaders)
// 	}
// }

// func TestSetServerName(t *testing.T) {
// 	wafConfig := NewWAFConfig()
// 	waf, err := NewWAF(wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	tx.SetServerName("Apache")
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedRequestHeaders := "Server: Apache\n"
// 	gotRequestHeaders := *txW.requestHeaders
// 	if expectedRequestHeaders != gotRequestHeaders {
// 		t.Errorf("Error setting server name: Expected: %s, Got: %s", expectedRequestHeaders, gotRequestHeaders)
// 	}
// }

// func TestReadRequestBodyFrom(t *testing.T){
// 	wafConfig := NewWAFConfig()
// 	waf, err := NewWAF(wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	body := "test"
// 	reader := strings.NewReader(body)
// 	tx.ReadRequestBodyFrom(reader)
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedRequestBody := "test"
// 	gotRequestBody := *txW.requestBody
// 	if expectedRequestBody != gotRequestBody {
// 		t.Errorf("Error reading request body: Expected: %s, Got: %s", expectedRequestBody, gotRequestBody)
// 	}
// }

// func TestAddResponseHeader(t *testing.T){
// 	wafConfig := NewWAFConfig()
// 	waf, err := NewWAF(wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedResponseHeaders := "content-type: application/x-www-form-urlencoded\n"
// 	gotResponseHeaders := *txW.responseHeaders
// 	if expectedResponseHeaders != gotResponseHeaders {
// 		t.Errorf("Error adding response header: Expected: %s, Got: %s", expectedResponseHeaders, gotResponseHeaders)
// 	}
// }

// func TestWriteResponseBody(t *testing.T){
// 	wafConfig := NewWAFConfig()
// 	waf, err := NewWAF(wafConfig)
// 	if err != nil {
// 		t.Errorf("Error creating WAF: %v", err)
// 	}
// 	tx := waf.NewTransaction()
// 	body := "test"
// 	tx.WriteResponseBody([]byte(body))
// 	txW, ok := tx.(WaceTransaction)
// 	if !ok {
// 		t.Errorf("Error casting to WaceTransaction")
// 	}
// 	expectedResponseBody := "test"
// 	gotResponseBody := *txW.responseBody
// 	if expectedResponseBody != gotResponseBody {
// 		t.Errorf("Error writing response body: Expected: %s, Got: %s", expectedResponseBody, gotResponseBody)
// 	}
// }