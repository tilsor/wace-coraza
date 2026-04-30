package waceWAF

import (
	"reflect"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/tilsor/ModSecIntl_wace_lib/configstore"
	"github.com/tilsor/ModSecIntl_wace_lib/pluginmanager"
)

func TestNewWaf(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()
	wafConfig := NewWAFConfig()
	_, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
}

func TestTransactionAddData(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf")

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
	expectedPayload := pluginmanager.HTTPPayload{
		URI:             "http://localhost:8090",
		Method:          "GET",
		HTTPVersion:     "HTTP/1.1",
		RequestHeaders:  []pluginmanager.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		RequestBody:     "test",
		ResponseHeaders: []pluginmanager.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		ResponseBody:    "test",
	}
	if !reflect.DeepEqual(*txW.httpPayload, expectedPayload) {
		t.Errorf("Error processing http payload: Expected: %v, Got: %v", expectedPayload, *txW.httpPayload)
	}
}

func TestTransactionWithIDAddData(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
	tx := waf.NewTransactionWithID("1234567890123456")
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
	expectedPayload := pluginmanager.HTTPPayload{
		URI:             "http://localhost:8090",
		Method:          "GET",
		HTTPVersion:     "HTTP/1.1",
		RequestHeaders:  []pluginmanager.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		RequestBody:     "test",
		ResponseHeaders: []pluginmanager.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		ResponseBody:    "test",
	}
	if !reflect.DeepEqual(*txW.httpPayload, expectedPayload) {
		t.Errorf("Error processing http payload: Expected: %v, Got: %v", expectedPayload, *txW.httpPayload)
	}
}

func TestTransactionProcess(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf")

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
	configFilePath = "testdata/config/waceconfig_block_transaction.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectives("SecAction \"id:15,phase:1,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=10',setvar:'tx.inbound_anomaly_score_threshold=5'\"")

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
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").WithDirectivesFromFile("testdata/config/waceexceptions.conf")

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

	tx.ProcessLogging()
}

func BenchmarkWaceTransactions(b *testing.B) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("../coraza.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
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
	configFilePath = "testdata/config/waceconfig_nats.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("../coraza.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
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

func BenchmarkCorazaTransactions(b *testing.B) {
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
