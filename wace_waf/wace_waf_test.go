package waceWAF

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/tilsor/ModSecIntl_wace_lib/configstore"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
)

func TestResolveConfigFilePathUsesEnvVar(t *testing.T) {
	expected := "/custom/path/config.yaml"
	t.Setenv(WACE_CONFIG_FILEPATH, expected)
	if got := resolveConfigFilePath(); got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestResolveConfigFilePathDefaultWhenEnvVarEmpty(t *testing.T) {
	t.Setenv(WACE_CONFIG_FILEPATH, "")
	if got := resolveConfigFilePath(); got != DEFAULT_CONFIG_FILEPATH {
		t.Errorf("expected default %q, got %q", DEFAULT_CONFIG_FILEPATH, got)
	}
}

func TestResolveConfigFilePathDefaultWhenEnvVarUnset(t *testing.T) {
	orig, wasSet := os.LookupEnv(WACE_CONFIG_FILEPATH)
	os.Unsetenv(WACE_CONFIG_FILEPATH)
	t.Cleanup(func() {
		if wasSet {
			os.Setenv(WACE_CONFIG_FILEPATH, orig)
		} else {
			os.Unsetenv(WACE_CONFIG_FILEPATH)
		}
	})
	if got := resolveConfigFilePath(); got != DEFAULT_CONFIG_FILEPATH {
		t.Errorf("expected default %q, got %q", DEFAULT_CONFIG_FILEPATH, got)
	}
}

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
// general config's: loadWaceAppConfig (the app-config path) always sets
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

// TestBlockTransactionsInMemoryAppConfigOverridesGeneralBlocking is the
// WithWaceAppConfig counterpart of
// TestBlockTransactionsAppConfigOverridesGeneralBlocking: an in-memory app
// configuration with blocking: true must take priority over the general
// config's blocking: false.
func TestBlockTransactionsInMemoryAppConfigOverridesGeneralBlocking(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_block_transaction_general_no_block.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConf := NewWaceWAFConfig().
		WithWaceAppConfig(WaceAppConfigFileData{
			ModelIds:      []string{"trivial", "trivial2"},
			DecisionIds:   []string{"weighted_sum"},
			EarlyBlocking: true,
			Blocking:      true,
		}).
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
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
		t.Error("transaction was not blocked, but the in-memory app config's blocking: true should take priority over the general config's blocking: false")
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

// exceptionsModelsByType maps each exception rule type to the only model of
// that type declared in waceconfig_all_models.yaml. waceexceptions.conf
// disables a model when the request URI contains its id.
var exceptionsModelsByType = map[string]string{
	"RequestHeaders":  "trivialRequestHeaders",
	"RequestBody":     "trivialRequestBody",
	"AllRequest":      "trivialAllRequest",
	"ResponseHeaders": "trivialResponseHeaders",
	"ResponseBody":    "trivialResponseBody",
	"AllResponse":     "trivialAllResponse",
}

// exceptionsActiveModels returns the models reported as active by the
// exceptions rule of the given type, and whether that rule was matched.
func exceptionsActiveModels(tx types.Transaction, exceptionType string) ([]string, bool) {
	for _, rule := range tx.(WaceTransaction).exceptionTransaction.MatchedRules() {
		if rule.Rule().ID() == gConfig.ruleIdsForExceptions[exceptionType] {
			return ParseActiveModels(rule.Message()), true
		}
	}
	return nil, false
}

// TestExceptions verifies that the exceptions file disables only the model
// whose exception is triggered, in every phase. With a URI that triggers no
// exception, every model must remain active; with a URI containing a model id,
// that model must be reported as inactive while the others stay active.
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
		t.Fatalf("Error creating WAF: %v", err.Error())
	}

	tests := []struct {
		name          string
		disabledModel string
	}{
		{name: "no exception triggered", disabledModel: ""},
		{name: "exception for trivialRequestHeaders", disabledModel: "trivialRequestHeaders"},
		{name: "exception for trivialRequestBody", disabledModel: "trivialRequestBody"},
		{name: "exception for trivialAllRequest", disabledModel: "trivialAllRequest"},
		{name: "exception for trivialResponseHeaders", disabledModel: "trivialResponseHeaders"},
		{name: "exception for trivialResponseBody", disabledModel: "trivialResponseBody"},
		{name: "exception for trivialAllResponse", disabledModel: "trivialAllResponse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := waf.NewTransaction()
			if tx == nil {
				t.Fatal("Error creating transaction")
			}
			defer tx.ProcessLogging()

			tx.ProcessURI("http://localhost:8090/"+tt.disabledModel, "GET", "HTTP/1.1")
			tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
			if i := tx.ProcessRequestHeaders(); i != nil {
				t.Errorf("request headers should not be blocked, got interruption: %v", i)
			}

			body := "test"
			_, count, err := tx.ReadRequestBodyFrom(strings.NewReader(body))
			if err != nil {
				t.Errorf("Error reading request body: %v", err.Error())
			}
			if count != len(body) {
				t.Errorf("Error reading request body: Expected bytes: %d, Got: %d", len(body), count)
			}
			i, err := tx.ProcessRequestBody()
			if err != nil {
				t.Errorf("Error processing request body: %v", err.Error())
			}
			if i != nil {
				t.Errorf("request body should not be blocked, got interruption: %v", i)
			}

			tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
			if i := tx.ProcessResponseHeaders(200, "HTTP/1.1"); i != nil {
				t.Errorf("response headers should not be blocked, got interruption: %v", i)
			}

			_, count, err = tx.WriteResponseBody([]byte(body))
			if err != nil {
				t.Errorf("Error writing response body: %v", err.Error())
			}
			if count != len(body) {
				t.Errorf("Error writing response body: Expected bytes: %d, Got: %d", len(body), count)
			}
			if _, err := tx.ProcessResponseBody(); err != nil {
				t.Errorf("Error processing response body: %v", err.Error())
			}

			for exceptionType, model := range exceptionsModelsByType {
				activeModels, found := exceptionsActiveModels(tx, exceptionType)
				if !found {
					t.Errorf("expected the %s exceptions rule to be matched", exceptionType)
					continue
				}
				expected := []string{model}
				if model == tt.disabledModel {
					expected = []string{}
				}
				if !reflect.DeepEqual(activeModels, expected) {
					t.Errorf("%s: expected active models %q, got %q", exceptionType, expected, activeModels)
				}
			}
		})
	}
}

// TestWithExceptionsFromFile verifies that WithExceptionsFromFile loads an
// exceptions file regardless of its name. The testdata exceptions file is
// copied under a name that WithDirectivesFromFile would not recognize, and the
// request URI triggers the exception that disables trivialRequestHeaders: the
// exceptions WAF must then report that model as inactive in phase 1.
func TestWithExceptionsFromFile(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	data, err := os.ReadFile("testdata/config/waceexceptions.conf")
	if err != nil {
		t.Fatalf("Error reading exceptions testdata: %v", err)
	}
	exceptionsPath := filepath.Join(t.TempDir(), "custom_exceptions.conf")
	if err := os.WriteFile(exceptionsPath, data, 0o600); err != nil {
		t.Fatalf("Error writing exceptions file: %v", err)
	}

	wafConf := NewWaceWAFConfig().
		WithExceptionsFromFile(exceptionsPath).
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err)
	}
	if waf.waceWafConfig.exceptionsFilePath != exceptionsPath {
		t.Fatalf("expected exceptionsFilePath %q, got %q", exceptionsPath, waf.waceWafConfig.exceptionsFilePath)
	}

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessURI("http://localhost:8090/trivialRequestHeaders", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Fatalf("request headers should not be blocked, got interruption: %v", i)
	}

	activeModels, found := exceptionsActiveModels(tx, "RequestHeaders")
	if !found {
		t.Fatal("expected the exceptions WAF to match the RequestHeaders exceptions rule")
	}
	if len(activeModels) != 0 {
		t.Errorf("expected trivialRequestHeaders to be disabled by the exceptions file, got active models %q", activeModels)
	}
}

// TestWithExceptionsFromFileNotFound verifies that a missing exceptions file
// makes WAF creation fail with an error that names the file.
func TestWithExceptionsFromFileNotFound(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	exceptionsPath := "testdata/config/missing_exceptions.conf"
	wafConf := NewWaceWAFConfig().
		WithWaceAppConfig(WaceAppConfigFileData{
			ModelIds:    []string{"trivial"},
			DecisionIds: []string{"weighted_sum"},
			DisableCRS:  true,
		}).
		WithExceptionsFromFile(exceptionsPath)

	_, err := NewWAF(wafConf)
	if err == nil {
		t.Fatal("expected WAF creation to fail with a missing exceptions file")
	}
	if !strings.Contains(err.Error(), "Error loading exceptions file") || !strings.Contains(err.Error(), exceptionsPath) {
		t.Errorf("expected an error loading %q, got: %v", exceptionsPath, err)
	}
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
