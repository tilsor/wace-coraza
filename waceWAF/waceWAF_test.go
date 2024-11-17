package waceWAF

import (
	// "strings"
	"os"
	"strings"
	"testing"

	coraza "github.com/corazawaf/coraza/v3"
	wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"
)

func TestNewWaf(t *testing.T) {
	file, err := os.ReadFile("testdata/waceconfig.yaml")
	if err != nil {
		t.Errorf("Error reading config file: %v", err.Error())
	}
	gConfig = new(generalConfig)
	gConfig.LoadGeneralConfigYaml(file)
	InitMetrics(ctx, gConfig.otelURL)
	wace.Init(getWaceMeter())
	wafConfig := NewWAFConfig()
	_, err = NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
}

func TestTransactionAddData(t *testing.T) {
	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/directives.conf")
	waceWafConf := wafConf.(*waceWAFConfig)
	waceWafConf.LoadConfigFromGeneralConfig(*gConfig)
	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
	tx := waf.NewTransaction()
	if tx == nil {
		t.Errorf("Error creating transaction")
	}
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	body := "test"
	reader := strings.NewReader(body)
	_, count, err := tx.ReadRequestBodyFrom(reader)
	if err != nil {
		t.Errorf("Error reading request body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error reading request body: Expected bytes: %d, Got: %d", len(body), count)
	}
	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	_, count, err = tx.WriteResponseBody([]byte(body))
	if err != nil {
		t.Errorf("Error writing response body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error writing response body: Expected bytes: %d, Got: %d", len(body), count)
	}
	txW, ok := tx.(WaceTransaction)
	if !ok {
		t.Errorf("Error casting to WaceTransaction")
	}
	expectedRequestLine := "GET http://localhost:8090 HTTP/1.1"
	gotRequestLine := *txW.requestLine
	if expectedRequestLine != gotRequestLine {
		t.Errorf("Error processing URI: Expected: %s, Got: %s", expectedRequestLine, gotRequestLine)
	}
	expectedRequestHeaders := "content-type: application/x-www-form-urlencoded\n"
	gotRequestHeaders := *txW.requestHeaders
	if expectedRequestHeaders != gotRequestHeaders {
		t.Errorf("Error adding request header: Expected: %s, Got: %s", expectedRequestHeaders, gotRequestHeaders)
	}
	expectedRequestBody := "test"
	gotRequestBody := *txW.requestBody
	if expectedRequestBody != gotRequestBody {
		t.Errorf("Error reading request body: Expected: %s, Got: %s", expectedRequestBody, gotRequestBody)
	}
	expectedResponseHeaders := "content-type: application/x-www-form-urlencoded\n"
	gotResponseHeaders := *txW.responseHeaders
	if expectedResponseHeaders != gotResponseHeaders {
		t.Errorf("Error adding response header: Expected: %s, Got: %s", expectedResponseHeaders, gotResponseHeaders)
	}
	expectedResponseBody := "test"
	gotResponseBody := *txW.responseBody
	if expectedResponseBody != gotResponseBody {
		t.Errorf("Error writing response body: Expected: %s, Got: %s", expectedResponseBody, gotResponseBody)
	}
}

func TestTransactionProcess(t *testing.T) {
	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/directives.conf")
	waceWafConf := wafConf.(*waceWAFConfig)
	waceWafConf.LoadConfigFromGeneralConfig(*gConfig)
	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
	tx := waf.NewTransaction()
	if tx == nil {
		t.Errorf("Error creating transaction")
	}
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.SetServerName("Apache")
	i := tx.ProcessRequestHeaders()
	if i != nil {
		t.Errorf("Error processing request headers that should not be blocked")
	}
	body := "test"
	reader := strings.NewReader(body)
	i, count, err := tx.ReadRequestBodyFrom(reader)
	if err != nil {
		t.Errorf("Error reading request body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error reading request body: Expected bytes: %d, Got: %d", len(body), count)
	}
	if i != nil {
		t.Errorf("Error reading request body that should not be blocked")
	}
	i, err = tx.ProcessRequestBody()
	if err != nil {
		t.Errorf("Error processing request body: %v", err.Error())
	}
	if i != nil {
		t.Errorf("Error processing request body that should not be blocked")
	}
	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	i = tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if i != nil {
		t.Errorf("Error processing response headers: %v", err.Error())
	}
	i, count, err = tx.WriteResponseBody([]byte(body))
	if err != nil {
		t.Errorf("Error writing response body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error writing response body: Expected bytes: %d, Got: %d", len(body), count)
	}
	if i != nil {
		t.Errorf("Error writing response body that should not be blocked")
	}
	i, err = tx.ProcessResponseBody()
	if err != nil {
		t.Errorf("Error processing response body: %v", err.Error())
	}
	if i != nil {
		t.Errorf("Error processing response body that should not be blocked")
	}
	tx.ProcessLogging()
}

func TestBlockTransactions(t *testing.T) {
	file, err := os.ReadFile("testdata/waceconfig_block_transaction.yaml")
	if err != nil {
		t.Errorf("Error reading config file: %v", err.Error())
	}
	gConfig = new(generalConfig)
	gConfig.LoadGeneralConfigYaml(file)
	InitMetrics(ctx, gConfig.otelURL)
	wace.Init(getWaceMeter())
	wafConfig := NewWAFConfig()
	wafConfig = wafConfig.WithDirectivesFromFile("testdata/directives.conf").
	WithDirectives("SecAction \"id:15,phase:1,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=10',setvar:'tx.inbound_anomaly_score_threshold=5'\"")
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}

	tx := waf.NewTransaction()
	if tx == nil {
		t.Errorf("Error creating transaction")
	}

	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.SetServerName("Apache")
	i := tx.ProcessRequestHeaders()
	if i == nil {
		t.Errorf("Error processing request headers that should be blocked")
	}

	body := "test"
	reader := strings.NewReader(body)
	i, count, err := tx.ReadRequestBodyFrom(reader)
	if err != nil {
		t.Errorf("Error reading request body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error reading request body: Expected bytes: %d, Got: %d", len(body), count)
	}
	i, err = tx.ProcessRequestBody()
	if err != nil {
		t.Errorf("Error processing request body: %v", err.Error())
	}
	if i == nil {
		t.Errorf("Error processing request body that should be blocked")
	}

	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	i = tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if i == nil {
		t.Errorf("Error processing response headers that should be blocked")
	}

	i, count, err = tx.WriteResponseBody([]byte(body))
	if err != nil {
		t.Errorf("Error writing response body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error writing response body: Expected bytes: %d, Got: %d", len(body), count)
	}
	if i != nil {
		t.Errorf("Error writing response body")
	}
	i, err = tx.ProcessResponseBody()
	if err != nil {
		t.Errorf("Error processing response body: %v", err.Error())
	}
	if i == nil {
		t.Errorf("Error processing response body that should be blocked")
	}
	tx.ProcessLogging()
}

func TestExceptions(t *testing.T) {
	file, err := os.ReadFile("testdata/waceconfig_all_models.yaml")
	if err != nil {
		t.Errorf("Error reading config file: %v", err.Error())
	}
	gConfig = new(generalConfig)
	gConfig.LoadGeneralConfigYaml(file)
	InitMetrics(ctx, gConfig.otelURL)
	wace.Init(getWaceMeter())
	wafConfig := NewWAFConfig()
	wafConfig = wafConfig.WithDirectivesFromFile("testdata/directives.conf").WithDirectivesFromFile("testdata/waceexceptions.conf")

	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}

	tx := waf.NewTransaction()
	if tx == nil {
		t.Errorf("Error creating transaction")
	}

	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	i := tx.ProcessRequestHeaders()
	if i != nil {
		t.Errorf("Error processing request headers that should not be blocked")
	}

	body := "test"
	reader := strings.NewReader(body)
	_, count, err := tx.ReadRequestBodyFrom(reader)
	if err != nil {
		t.Errorf("Error reading request body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error reading request body: Expected bytes: %d, Got: %d", len(body), count)
	}
	i, err = tx.ProcessRequestBody()
	if err != nil {
		t.Errorf("Error processing request body: %v", err.Error())
	}
	if i != nil {
		t.Errorf("Error processing request body that should not be blocked")
	}

	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	i = tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if i != nil {
		t.Errorf("Error processing response headers: %v", err.Error())
	}

	_, count, err = tx.WriteResponseBody([]byte(body))
	if err != nil {
		t.Errorf("Error writing response body: %v", err.Error())
	}
	if count != len(body) {
		t.Errorf("Error writing response body: Expected bytes: %d, Got: %d", len(body), count)
	}
	i, err = tx.ProcessResponseBody()
	if err != nil {
		t.Errorf("Error processing response body: %v", err.Error())
	}
}


func BenchmarkWaceTransactions(b *testing.B) {
	file, err := os.ReadFile("testdata/waceconfig.yaml")
	if err != nil {
		b.Errorf("Error reading config file: %v", err.Error())
	}
	gConfig = new(generalConfig)
	gConfig.LoadGeneralConfigYaml(file)
	InitMetrics(ctx, gConfig.otelURL)
	wace.Init(getWaceMeter())
	wafConfig := NewWAFConfig()
	wafConfig = wafConfig.WithDirectivesFromFile("../coraza.conf").
	WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
	WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := NewWAF(wafConfig)
	if err != nil {
		b.Errorf("Error creating WAF: %v", err.Error())
	}
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		if tx == nil {
			b.Errorf("Error creating transaction")
		}
		tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
		tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
		tx.SetServerName("Apache")
		tx.ProcessRequestHeaders()
		body := "test"
		reader := strings.NewReader(body)
		tx.ReadRequestBodyFrom(reader)
		tx.ProcessRequestBody()
		tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		tx.WriteResponseBody([]byte(body))
		tx.ProcessResponseBody()
		tx.ProcessLogging()
	}
}

func BenchmarkWaceTransactionsNATS(b *testing.B) {
	file, err := os.ReadFile("testdata/waceconfig_nats.yaml")
	if err != nil {
		b.Errorf("Error reading config file: %v", err.Error())
	}
	gConfig = new(generalConfig)
	gConfig.LoadGeneralConfigYaml(file)
	InitMetrics(ctx, gConfig.otelURL)
	wace.Init(getWaceMeter())
	wafConfig := NewWAFConfig()
	wafConfig = wafConfig.WithDirectivesFromFile("../coraza.conf").
	WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
	WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := NewWAF(wafConfig)
	if err != nil {
		b.Errorf("Error creating WAF: %v", err.Error())
	}
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		if tx == nil {
			b.Errorf("Error creating transaction")
		}
		tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
		tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
		tx.SetServerName("Apache")
		tx.ProcessRequestHeaders()
		body := "test"
		reader := strings.NewReader(body)
		tx.ReadRequestBodyFrom(reader)
		tx.ProcessRequestBody()
		tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		tx.WriteResponseBody([]byte(body))
		tx.ProcessResponseBody()
		tx.ProcessLogging()
	}
}

func BenchmarkCorazaTransactions(b *testing.B){
	wafConfig := coraza.NewWAFConfig()
	wafConfig = wafConfig.WithDirectivesFromFile("../coraza.conf").
	WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
	WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		b.Errorf("Error creating WAF: %v", err.Error())
	}
	for i := 0; i < b.N; i++ {
		tx := waf.NewTransaction()
		if tx == nil {
			b.Errorf("Error creating transaction")
		}
		tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
		tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
		tx.SetServerName("Apache")
		tx.ProcessRequestHeaders()
		body := "test"
		reader := strings.NewReader(body)
		tx.ReadRequestBodyFrom(reader)
		tx.ProcessRequestBody()
		tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
		tx.ProcessResponseHeaders(200, "HTTP/1.1")
		tx.WriteResponseBody([]byte(body))
		tx.ProcessResponseBody()
		tx.ProcessLogging()
	}
}