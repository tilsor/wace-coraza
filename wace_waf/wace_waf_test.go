package waceWAF

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/tilsor/ModSecIntl_wace_lib/configstore"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
)

// resetWACE drops the configuration so the next test initializes WACE
// again.
func resetWACE() {
	gConfig = nil
	configstore.Clean()
}

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

	defer resetWACE()
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

	defer resetWACE()

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
	defer tx.ProcessLogging()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Errorf("request headers should not be blocked, got interruption: %v", i)
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
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Errorf("Error processing request body: %v", err.Error())
	}
	tx.AddResponseHeader("content-type", "text/plain")
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
	txW, ok := tx.(WaceTransaction)
	if !ok {
		t.Errorf("Error casting to WaceTransaction")
	}
	expectedPayload := waceapi.HTTPPayload{
		URI:         "http://localhost:8090",
		Method:      "GET",
		HTTPVersion: "HTTP/1.1",
		RequestHeaders: []waceapi.HTTPHeader{
			{Key: "Host", Value: "localhost"},
			{Key: "content-type", Value: "application/x-www-form-urlencoded"},
		},
		RequestBody:      "test",
		ResponseCode:     200,
		ResponseProtocol: "HTTP/1.1",
		ResponseHeaders:  []waceapi.HTTPHeader{{Key: "content-type", Value: "text/plain"}},
		ResponseBody:     "test",
	}
	if !reflect.DeepEqual(*txW.httpPayload, expectedPayload) {
		t.Errorf("Error processing http payload: Expected: %v, Got: %v", expectedPayload, *txW.httpPayload)
	}
}

func TestTransactionWithIDAddData(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer resetWACE()

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
	defer tx.ProcessLogging()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Errorf("request headers should not be blocked, got interruption: %v", i)
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
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Errorf("Error processing request body: %v", err.Error())
	}
	tx.AddResponseHeader("content-type", "text/plain")
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
	txW, ok := tx.(WaceTransaction)
	if !ok {
		t.Errorf("Error casting to WaceTransaction")
	}
	expectedPayload := waceapi.HTTPPayload{
		URI:         "http://localhost:8090",
		Method:      "GET",
		HTTPVersion: "HTTP/1.1",
		RequestHeaders: []waceapi.HTTPHeader{
			{Key: "Host", Value: "localhost"},
			{Key: "content-type", Value: "application/x-www-form-urlencoded"},
		},
		RequestBody:      "test",
		ResponseCode:     200,
		ResponseProtocol: "HTTP/1.1",
		ResponseHeaders:  []waceapi.HTTPHeader{{Key: "content-type", Value: "text/plain"}},
		ResponseBody:     "test",
	}
	if !reflect.DeepEqual(*txW.httpPayload, expectedPayload) {
		t.Errorf("Error processing http payload: Expected: %v, Got: %v", expectedPayload, *txW.httpPayload)
	}
}

func TestTransactionProcess(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer resetWACE()

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

	defer resetWACE()

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

	defer resetWACE()

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

	defer resetWACE()

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

	defer resetWACE()

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

	defer resetWACE()

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

// TestBlockTransactionsEverythingModel verifies that an Everything model is
// only analyzed in phase 4: with it as the only model, phases 1 to 3 must not
// block (only the low CRS anomaly score counts there), while phase 4 must block
// because the model reports a 1.0 probability of attack and outweighs the WAF.
func TestBlockTransactionsEverythingModel(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_everything_block.yaml"
	gConfig = nil

	defer resetWACE()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err.Error())
	}

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Errorf("request headers should not be blocked, got interruption: %v", i)
	}

	body := "test"
	if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
		t.Errorf("Error reading request body: %v", err.Error())
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

	if _, _, err := tx.WriteResponseBody([]byte(body)); err != nil {
		t.Errorf("Error writing response body: %v", err.Error())
	}
	i, err = tx.ProcessResponseBody()
	if err != nil {
		t.Errorf("Error processing response body: %v", err.Error())
	}
	if i == nil {
		t.Errorf("response body should be blocked by the Everything model")
	}
}

// exceptionsModelsByType maps each exception rule type to the only model of
// that type declared in waceconfig_all_models.yaml. waceexceptions.conf
// disables a model when the request URI contains its id.
var exceptionsModelsByType = map[configstore.ModelPluginType]string{
	configstore.RequestHeaders:  "trivialRequestHeaders",
	configstore.RequestBody:     "trivialRequestBody",
	configstore.AllRequest:      "trivialAllRequest",
	configstore.ResponseHeaders: "trivialResponseHeaders",
	configstore.ResponseBody:    "trivialResponseBody",
	configstore.AllResponse:     "trivialAllResponse",
	configstore.Everything:      "trivialEverything",
}

// TestExceptions verifies that the exceptions file disables only the model
// whose exception is triggered, in every phase. With a URI that triggers no
// exception, every model must remain active; with a URI containing a model id,
// that model must be reported as inactive while the others stay active.
//
// It runs against two exceptions files: one where every exception rule runs in
// phase 1, and one where each rule runs in the phase of its model type. The
// latter checks that the rule reporting the active models of a type runs in
// that type's phase: if it ran earlier, it would report the models as active
// before a later-phase exception disabled them.
func TestExceptions(t *testing.T) {
	exceptionsFiles := []string{
		"testdata/config/waceexceptions.conf",
		"testdata/config/waceexceptions_phases.conf",
	}
	for _, exceptionsFile := range exceptionsFiles {
		t.Run(filepath.Base(exceptionsFile), func(t *testing.T) {
			testExceptions(t, exceptionsFile)
		})
	}
}

func testExceptions(t *testing.T, exceptionsFile string) {
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	defer resetWACE()

	wafConf := NewWaceWAFConfig().
		WithExceptionsFromFile(exceptionsFile).
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

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
		{name: "exception for trivialEverything", disabledModel: "trivialEverything"},
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
				activeModels, found := tx.(WaceTransaction).exceptionActiveModels(exceptionType)
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

	defer resetWACE()

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

	activeModels, found := tx.(WaceTransaction).exceptionActiveModels(configstore.RequestHeaders)
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

	defer resetWACE()

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

	defer resetWACE()

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

// benchRunCounter makes the remote model ids of each benchmark run unique.
var benchRunCounter atomic.Uint64

// newBenchWaceWAF creates a WACE WAF with the general config at
// configPath and the CRS, and resets WACE when the benchmark ends.
func newBenchWaceWAF(b *testing.B, configPath string) coraza.WAF {
	b.Helper()
	configFilePath = configPath
	gConfig = nil
	// Logs share stdout with the results under go test and would break
	// the lines benchstat parses.
	SetLogger(slog.New(slog.DiscardHandler))
	b.Cleanup(func() {
		resetWACE()
		SetLogger(nil)
	})

	wafConf := NewWAFConfig().WithDirectivesFromFile("../coraza.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := NewWAF(wafConf)
	if err != nil {
		b.Fatalf("Error creating WAF: %v", err)
	}
	return waf
}

// newBenchCorazaWAF creates a plain Coraza WAF with the CRS, as a baseline
// for the WACE benchmarks.
func newBenchCorazaWAF(b *testing.B) coraza.WAF {
	b.Helper()
	wafConf := coraza.NewWAFConfig().WithDirectivesFromFile("../coraza.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := coraza.NewWAF(wafConf)
	if err != nil {
		b.Fatalf("Error creating WAF: %v", err)
	}
	return waf
}

// runBenchTransaction drives a whole transaction through every phase,
// the same way the Coraza HTTP middleware does.
func runBenchTransaction(b *testing.B, waf coraza.WAF) {
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.SetServerName("Apache")
	tx.ProcessRequestHeaders()
	body := "test"
	if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
		b.Errorf("Error reading request body: %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		b.Errorf("Error processing request body: %v", err)
	}
	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	if _, _, err := tx.WriteResponseBody([]byte(body)); err != nil {
		b.Errorf("Error writing response body: %v", err)
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		b.Errorf("Error processing response body: %v", err)
	}
}

// BenchmarkWaceTransactions measures a full transaction with local sync
// model plugins, one transaction at a time.
func BenchmarkWaceTransactions(b *testing.B) {
	waf := newBenchWaceWAF(b, "testdata/config/waceconfig.yaml")
	b.ReportAllocs()
	for b.Loop() {
		runBenchTransaction(b, waf)
	}
}

// BenchmarkWaceTransactionsParallel is BenchmarkWaceTransactions with
// GOMAXPROCS transactions in flight at the same time.
func BenchmarkWaceTransactionsParallel(b *testing.B) {
	waf := newBenchWaceWAF(b, "testdata/config/waceconfig.yaml")
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runBenchTransaction(b, waf)
		}
	})
}

// BenchmarkWaceTransactionsNATS measures a full transaction with remote
// sync model plugins, which round-trip through NATS. It needs a NATS
// server, given in WACE_BENCH_NATS_URL (e.g. nats://localhost:4222), and
// is skipped otherwise. The model side runs in this same process.
func BenchmarkWaceTransactionsNATS(b *testing.B) {
	natsURL := os.Getenv("WACE_BENCH_NATS_URL")
	if natsURL == "" {
		b.Skip("WACE_BENCH_NATS_URL not set")
	}
	// NATS handlers are never stopped, so every run (including each
	// -count repetition) needs its own model ids, or the handlers left
	// over from earlier runs answer too.
	run := benchRunCounter.Add(1)
	model1 := fmt.Sprintf("trivial-%d", run)
	model2 := fmt.Sprintf("trivial2-%d", run)
	conf := fmt.Sprintf(`nats_url: %q
model_plugins:
  - id: %q
    plugin_type: RequestHeaders
    path: "testdata/plugins/trivial.so"
    remote: true
  - id: %q
    plugin_type: RequestHeaders
    path: "testdata/plugins/trivial2.so"
    remote: true
decision_plugins:
  - id: "weighted_sum"
    path: "testdata/plugins/weighted_sum.so"
    model_weights:
      %s: 0.25
      %s: 0.25
    waf_weight: 0.5
    params:
      threshold: "0.5"
crs_version: "4.4.0-dev"
exception_ids:
  RequestHeaders: 100
  RequestBody: 200
  AllRequest: 300
  ResponseHeaders: 400
  ResponseBody: 500
  AllResponse: 600
`, natsURL, model1, model2, model1, model2)
	configPath := filepath.Join(b.TempDir(), "waceconfig.yaml")
	if err := os.WriteFile(configPath, []byte(conf), 0o644); err != nil {
		b.Fatalf("Error writing config: %v", err)
	}

	waf := newBenchWaceWAF(b, configPath)
	// give the subscriptions time to reach the server
	time.Sleep(100 * time.Millisecond)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		runBenchTransaction(b, waf)
	}
}

// BenchmarkCorazaTransactions is the baseline: the same transaction on
// plain Coraza with the CRS, without WACE.
func BenchmarkCorazaTransactions(b *testing.B) {
	waf := newBenchCorazaWAF(b)
	b.ReportAllocs()
	for b.Loop() {
		runBenchTransaction(b, waf)
	}
}

// BenchmarkCorazaTransactionsParallel is the baseline of
// BenchmarkWaceTransactionsParallel.
func BenchmarkCorazaTransactionsParallel(b *testing.B) {
	waf := newBenchCorazaWAF(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			runBenchTransaction(b, waf)
		}
	})
}

// newExceptionsBodyWAF returns a WAF with an exceptions file whose body access
// is enabled through WithRequestBodyAccess and WithResponseBodyAccess, so both
// the main and the exceptions transactions have access to the bodies.
func newExceptionsBodyWAF(t *testing.T) *WaceWAF {
	t.Helper()
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	wafConf := NewWaceWAFConfig().
		WithExceptionsFromFile("testdata/config/waceexceptions.conf").
		WithRequestBodyAccess().
		WithResponseBodyAccess().
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err.Error())
	}
	return waf
}

// TestRequestBodyWithExceptions verifies that the CRS inspects the request
// body when the exceptions transaction also has access to it, and that the
// exceptions transaction and the models get the same body.
func TestRequestBodyWithExceptions(t *testing.T) {
	defer resetWACE()
	waf := newExceptionsBodyWAF(t)

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessURI("http://localhost:8090", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Fatalf("request headers should not be blocked, got interruption: %v", i)
	}

	body := "user=password"
	if _, _, err := tx.ReadRequestBodyFrom(strings.NewReader(body)); err != nil {
		t.Fatalf("Error reading request body: %v", err.Error())
	}
	i, err := tx.ProcessRequestBody()
	if err != nil {
		t.Fatalf("Error processing request body: %v", err.Error())
	}
	if i == nil || i.Status != 403 {
		t.Errorf("request body should be blocked by rule 100, got interruption: %v", i)
	}

	txW := tx.(WaceTransaction)
	if txW.httpPayload.RequestBody != body {
		t.Errorf("expected models request body %q, got %q", body, txW.httpPayload.RequestBody)
	}
	got, err := bodyString(txW.exceptionTransaction.RequestBodyReader())
	if err != nil {
		t.Fatalf("Error reading the exceptions request body: %v", err)
	}
	if got != body {
		t.Errorf("expected exceptions request body %q, got %q", body, got)
	}
}

// TestResponseBodyChunks verifies that the models and the exceptions
// transaction get the whole response body when it is written in chunks.
func TestResponseBodyChunks(t *testing.T) {
	defer resetWACE()
	waf := newExceptionsBodyWAF(t)

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Fatalf("request headers should not be blocked, got interruption: %v", i)
	}
	if i, err := tx.ProcessRequestBody(); i != nil || err != nil {
		t.Fatalf("request body should not be blocked, got interruption: %v, error: %v", i, err)
	}

	tx.AddResponseHeader("content-type", "text/plain")
	if i := tx.ProcessResponseHeaders(200, "HTTP/1.1"); i != nil {
		t.Fatalf("response headers should not be blocked, got interruption: %v", i)
	}
	chunks := []string{"first ", "second ", "third"}
	for _, chunk := range chunks {
		if _, _, err := tx.WriteResponseBody([]byte(chunk)); err != nil {
			t.Fatalf("Error writing response body: %v", err.Error())
		}
	}
	if _, err := tx.ProcessResponseBody(); err != nil {
		t.Fatalf("Error processing response body: %v", err.Error())
	}

	body := strings.Join(chunks, "")
	txW := tx.(WaceTransaction)
	if txW.httpPayload.ResponseBody != body {
		t.Errorf("expected models response body %q, got %q", body, txW.httpPayload.ResponseBody)
	}
	got, err := bodyString(txW.exceptionTransaction.ResponseBodyReader())
	if err != nil {
		t.Fatalf("Error reading the exceptions response body: %v", err)
	}
	if got != body {
		t.Errorf("expected exceptions response body %q, got %q", body, got)
	}
}

// TestRequestBodyProcessPartial verifies that, with ProcessPartial, the
// request body is not read beyond the limit: the models get the body up to
// the limit and the rest is left in the reader for the backend.
func TestRequestBodyProcessPartial(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer resetWACE()

	const limit = 10
	wafConf := NewWAFConfig().
		WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectives("SecRequestBodyLimitAction ProcessPartial").
		WithRequestBodyLimit(limit).
		WithRequestBodyInMemoryLimit(limit)

	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err.Error())
	}

	tx := waf.NewTransaction()
	defer tx.ProcessLogging()

	tx.ProcessURI("http://localhost:8090", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "localhost")
	tx.AddRequestHeader("content-type", "text/plain")
	if i := tx.ProcessRequestHeaders(); i != nil {
		t.Fatalf("request headers should not be blocked, got interruption: %v", i)
	}

	body := "0123456789abcdefghij"
	// bufio.Reader hides the length of the body, as a network body would.
	r := bufio.NewReader(strings.NewReader(body))
	if _, _, err := tx.ReadRequestBodyFrom(r); err != nil {
		t.Fatalf("Error reading request body: %v", err.Error())
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("Error processing request body: %v", err.Error())
	}

	if got := tx.(WaceTransaction).httpPayload.RequestBody; got != body[:limit] {
		t.Errorf("expected models request body %q, got %q", body[:limit], got)
	}
	rest, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("Error reading the rest of the body: %v", err)
	}
	if string(rest) != body[limit:] {
		t.Errorf("expected the rest of the body %q left in the reader, got %q", body[limit:], rest)
	}
}
