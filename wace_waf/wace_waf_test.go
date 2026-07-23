package waceWAF

import (
	"reflect"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/tilsor/ModSecIntl_wace_lib/configstore"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
)

func TestNewWaf(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()
	wafConfig := NewWAFConfig().
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")
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

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

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
	expectedPayload := waceapi.HTTPPayload{
		URI:             "http://localhost:8090",
		Method:          "GET",
		HTTPVersion:     "HTTP/1.1",
		RequestHeaders:  []waceapi.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		RequestBody:     "test",
		ResponseHeaders: []waceapi.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
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

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

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
	expectedPayload := waceapi.HTTPPayload{
		URI:             "http://localhost:8090",
		Method:          "GET",
		HTTPVersion:     "HTTP/1.1",
		RequestHeaders:  []waceapi.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
		RequestBody:     "test",
		ResponseHeaders: []waceapi.HTTPHeader{{Key: "content-type", Value: "application/x-www-form-urlencoded"}},
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

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err.Error())
	}
	tx := waf.NewTransaction()
	if tx == nil {
		t.Errorf("Error creating transaction")
	}
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("Host", "Test")
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
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
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

// TestBlockTransactionsBlockingDisabled mirrors TestBlockTransactions with
// blocking: false in the general config. The anomaly score still crosses the
// threshold (same directives and models), but the transaction must not be
// denied: the blocking config flag gates whether WACE's decision actually
// results in an interruption, independent of the decision plugin's result.
func TestBlockTransactionsBlockingDisabled(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_block_transaction_blocking_disabled.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
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
	if i != nil {
		t.Errorf("transaction was blocked but must not be: blocking is disabled")
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
	if i != nil {
		t.Errorf("transaction was blocked but must not be: blocking is disabled")
	}

	tx.ProcessLogging()
}

// TestBlockTransactionsAppConfigOverridesGeneralBlocking verifies that a
// per-app waceappconfig.yaml's blocking value takes priority over the
// general config's: LoadConfigYaml (the app-config path) always sets
// blocking from the app config, never falling back to the general config's
// value the way LoadConfigFromGeneralConfig does. Here the general config
// has blocking: false but the app config has blocking: true, so the
// transaction must still be denied.
func TestBlockTransactionsAppConfigOverridesGeneralBlocking(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_block_transaction_general_no_block.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectivesFromFile("testdata/config/appoverridewaceappconfig.yaml").
		WithDirectives("SecAction \"id:15,phase:1,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=10',setvar:'tx.inbound_anomaly_score_threshold=5'\"")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err.Error())
	}

	tx := waf.NewTransaction()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.SetServerName("Apache")
	i := tx.ProcessRequestHeaders()
	if i == nil {
		t.Error("transaction was not blocked, but the app config's blocking: true should take priority over the general config's blocking: false")
	}

	tx.ProcessLogging()
}

// TestVirtualPatchingWithCRSDisabled verifies that Coraza's own SecLang rules
// still produce interruptions when CRS is disabled (disable_crs: true skips
// only the WACE-injected CRS directives from getConfigRules, not Coraza rule
// evaluation itself). This is the classic virtual-patching use case: a
// hand-written rule blocking a known-bad request without CRS loaded at all.
func TestVirtualPatchingWithCRSDisabled(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().
		WithDirectivesFromFile("testdata/config/disablecrswaceappconfig.yaml").
		WithDirectives(`SecRule REQUEST_URI "@streq /admin" "id:1000001,phase:1,deny,status:403,msg:'Virtual patch: blocked /admin'"`)

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err.Error())
	}

	tests := []struct {
		name        string
		uri         string
		wantBlocked bool
	}{
		{name: "matches virtual patch rule", uri: "/admin", wantBlocked: true},
		{name: "does not match virtual patch rule", uri: "/", wantBlocked: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := waf.NewTransaction()
			tx.ProcessURI(tt.uri, "GET", "HTTP/1.1")
			tx.AddRequestHeader("Host", "test")
			i := tx.ProcessRequestHeaders()
			if tt.wantBlocked && i == nil {
				t.Errorf("expected virtual-patch rule to block %q even with CRS disabled", tt.uri)
			}
			if !tt.wantBlocked && i != nil {
				t.Errorf("expected %q to pass through, got interruption: %v", tt.uri, i)
			}
			tx.ProcessLogging()
		})
	}
}

func TestExceptions(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectivesFromFile("testdata/config/waceexceptions.conf")

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

// TestTrainingModelNotUsedInDecision verifies that a model in training mode
// does not contribute to the decision plugin, even if it would cause a block
// in sync mode. Compare with TestBlockTransactions which uses trivial2 as a
// sync model and expects a block.
func TestTrainingModelNotUsedInDecision(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_training_no_block.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	// Set WAF anomaly scores to zero so only model scores can trigger blocking.
	// trivial2 (weight=1, attack=1.0) is in training mode and must be excluded
	// from the decision. trivial (weight=0, attack=0.0) is the only sync model.
	wafConf := NewWAFConfig().
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectives("SecAction \"id:15,phase:1,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=0',setvar:'tx.inbound_anomaly_score_threshold=5'\"")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err)
	}

	tx := waf.NewTransaction()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("Host", "Test")

	i := tx.ProcessRequestHeaders()
	if i != nil {
		t.Error("transaction was blocked but must not be: trivial2 is in training mode and must not contribute to the decision")
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
