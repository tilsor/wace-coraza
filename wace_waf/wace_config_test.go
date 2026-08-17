package waceWAF

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/tilsor/ModSecIntl_wace_lib/configstore"
)

// testRuleMetadata is a minimal types.RuleMetadata used to build matched rules
// in tests. It embeds the interface so only the methods actually exercised by
// the code under test (ID) need to be implemented; any other call would panic,
// which is the intended signal that a test relies on an unmocked method.
type testRuleMetadata struct {
	types.RuleMetadata
	id int
}

func (r testRuleMetadata) ID() int { return r.id }

// testMatchedRule is a minimal types.MatchedRule for tests, exposing only the
// rule id and the (already macro-expanded) message read by parseScoreParams.
type testMatchedRule struct {
	types.MatchedRule
	id      int
	message string
}

func (m testMatchedRule) Rule() types.RuleMetadata { return testRuleMetadata{id: m.id} }
func (m testMatchedRule) Message() string          { return m.message }

func matchedRule(id int, message string) types.MatchedRule {
	return testMatchedRule{id: id, message: message}
}

func TestGetConfigRules(t *testing.T) {
	crsBlockingRules := []string{
		`SecRuleUpdateActionById 949111 "pass"`,
		`SecRuleUpdateActionById 949110 "pass"`,
		`SecRuleUpdateActionById 959101 "pass"`,
		`SecRuleUpdateActionById 959100 "pass"`,
	}

	// Coraza (and this integration) only supports CRS v4 and later, so the
	// rule set must be the same regardless of the CRS version string, as
	// long as one is actually configured.
	for _, version := range []string{"4.4", "4.4.0-dev", "5.0"} {
		cfg := waceWAFConfig{earlyBlocking: false}
		rules := cfg.getConfigRules(version)

		if len(rules) != 8 {
			t.Fatalf("version %q: expected 8 rules, got %d: %v", version, len(rules), rules)
		}

		// CRS's own blocking rules must be neutralized via
		// SecRuleUpdateActionById (so they stay in the audit trail), not
		// removed via SecRuleRemoveById.
		for i, expected := range crsBlockingRules {
			if rules[i] != expected {
				t.Errorf("version %q: expected rule %d to be %q, got: %s", version, i, expected, rules[i])
			}
		}

		for phase := 1; phase <= 4; phase++ {
			rule := rules[phase+3]
			id := reportingRuleIDs[strconv.Itoa(phase)]
			if !strings.Contains(rule, fmt.Sprintf("id:%d,phase:%d,", id, phase)) {
				t.Errorf("version %q phase %d: expected reporting rule with id:%d,phase:%d, got: %s", version, phase, id, phase, rule)
			}
			if !strings.Contains(rule, "tag:'reporting'") {
				t.Errorf("version %q phase %d: reporting rule missing tag:'reporting': %s", version, phase, rule)
			}
			if !strings.Contains(rule, "COMBINED_SCORE=%{tx.anomaly_score}") {
				t.Errorf("version %q phase %d: reporting rule missing COMBINED_SCORE: %s", version, phase, rule)
			}
		}
	}

	// An empty CRS version means the operator did not configure CRS, so no
	// CRS-specific directives should be emitted: SecRuleUpdateActionById
	// (unlike SecRuleRemoveById) fails WAF creation if its target rule id
	// isn't loaded, so this must not assume CRS's rules exist.
	cfgNoCRS := waceWAFConfig{earlyBlocking: false}
	rulesNoCRS := cfgNoCRS.getConfigRules("")
	if len(rulesNoCRS) != 0 {
		t.Errorf("expected no rules when CRS version is empty, got: %v", rulesNoCRS)
	}

	// early_blocking inserts an id'd setvar rule right after the CRS
	// blocking rules are neutralized and before the reporting rules.
	cfgEarly := waceWAFConfig{earlyBlocking: true}
	rulesEarly := cfgEarly.getConfigRules("4.4")
	if len(rulesEarly) != 9 {
		t.Fatalf("expected 9 rules with early_blocking, got %d: %v", len(rulesEarly), rulesEarly)
	}
	if rulesEarly[4] != `SecAction "id:9011150,phase:1,setvar:'tx.early_blocking=1'"` {
		t.Errorf("expected early_blocking setvar rule at index 4, got: %s", rulesEarly[4])
	}

	// early_blocking must still be a no-op (no rules) when CRS isn't loaded.
	cfgEarlyNoCRS := waceWAFConfig{earlyBlocking: true}
	if rules := cfgEarlyNoCRS.getConfigRules(""); len(rules) != 0 {
		t.Errorf("expected no rules when CRS version is empty even with early_blocking, got: %v", rules)
	}

	// Reporting rule ids must be distinct (Coraza rejects duplicate rule
	// ids) and must not collide with a real CRS rule id, since they are
	// injected into the same WAF as the CRS rule files. This also covers
	// the early_blocking setvar rule's id (9011150), which previously used
	// 901115 - a real CRS rule id (REQUEST-901-INITIALIZATION.conf) - and
	// broke WAF creation with "duplicated rule id 901115".
	seen := map[int]bool{9011150: true}
	realCRSIDs := map[int]bool{949110: true, 959100: true, 949111: true, 959101: true, 901115: true}
	for id := range seen {
		if realCRSIDs[id] {
			t.Errorf("rule id %d collides with a real CRS rule id", id)
		}
	}
	for _, phase := range []string{"1", "2", "3", "4"} {
		id := reportingRuleIDs[phase]
		if seen[id] {
			t.Errorf("reporting rule id %d is reused across phases or collides with the early_blocking rule id", id)
		}
		seen[id] = true
		if realCRSIDs[id] {
			t.Errorf("reporting rule id %d collides with a real CRS rule id", id)
		}
	}
}

func TestNewConfig(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig().
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf")
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err)
	}
	conf := waf.waceWafConfig.waceModels
	if conf == nil {
		t.Errorf("Error creating WaceConfig")
	}

	expected := &WaceModels{
		reqHeadModelIDs:  []string{"trivial"},
		reqBodyModelIDs:  []string{"trivial2"},
		reqModelIDs:      []string{},
		respHeadModelIDs: []string{},
		respBodyModelIDs: []string{},
		respModelIDs:     []string{},
	}

	if !reflect.DeepEqual(gConfig.waceModels, expected) {
		t.Errorf("Error: models do not match expected %v, got %v", expected, conf)
	}
}

func TestParseUnexceptedModels(t *testing.T) {
	exceptionRuleMessage := "model1:true,model2:false,model3:true,"
	models := ParseActiveModels(exceptionRuleMessage)
	if len(models) != 2 {
		t.Errorf("Error parsing unexcepted models: Expected 2, Got %d", len(models))
	}
	if models[0] != "model1" && models[1] != "model1" {
		t.Errorf("Error parsing unexcepted models: Expected 'model1', Got %s and %s", models[0], models[1])
	}
	if models[0] != "model3" && models[1] != "model3" {
		t.Errorf("Error parsing unexcepted models: Expected 'model3', Got %s and %s", models[0], models[1])
	}
}

func TestGeneralConfigLoadConfig(t *testing.T) {
	gConfig := generalConfig{}
	configFilePath := "testdata/config/waceconfig.yaml"

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		t.Fatalf("Error loading general config: %v", err)
	}
	_, err = gConfig.LoadConfig(data)
	if err != nil {
		t.Fatalf("Error loading general config: %v", err)
	}

	if gConfig.crsVersion == "" {
		// CRS Version is not set in the config file
		t.Error("CRS Version was not loaded properly")
	}
}

// Ejemplo de prueba para waceWAFConfig.LoadConfig
func TestWaceWAFConfigLoadConfig(t *testing.T) {
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
		t.Errorf("Error creating WAF: %v", err)
	}

	wConfig := waceWAFConfig{}
	filePath := "testdata/config/app1waceappconfig.yaml"

	err = wConfig.LoadConfig(filePath)
	if err != nil {
		t.Fatalf("Error loading waceappconfig: %v", err)
	}

	if len(wConfig.waceDecisionIds) == 0 {
		t.Error("Decision Plugin Ids were not loaded properly")
	}

	if len(wConfig.waceModels.reqHeadModelIDs) == 0 {
		t.Errorf("Model Plugin Ids were not loaded properly, expected %d model Id, got %d", 1, len(wConfig.waceModels.reqHeadModelIDs))
	}
}

// TestWaceWAFConfigLoadConfigNewFields verifies that LoadConfigYaml parses the
// early_blocking, disable_crs, blocking and app_name fields from a
// per-app waceappconfig.yaml file.
func TestWaceWAFConfigLoadConfigNewFields(t *testing.T) {
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
		t.Fatalf("Error creating WAF: %v", err)
	}

	wConfig := waceWAFConfig{}
	err = wConfig.LoadConfig("testdata/config/app2waceappconfig.yaml")
	if err != nil {
		t.Fatalf("Error loading waceappconfig: %v", err)
	}

	if !wConfig.earlyBlocking {
		t.Error("expected earlyBlocking to be true")
	}
	if !wConfig.disableCRS {
		t.Error("expected disableCRS to be true")
	}
	if !wConfig.blocking {
		t.Error("expected blocking to be true")
	}
}

// TestLoadConfigFromGeneralConfigPropagatesBlocking is a regression test:
// LoadConfigFromGeneralConfig (the path used when no per-app waceappconfig.yaml
// is provided) must fall back to the general configuration's blocking value,
// the same way it already does for earlyBlocking. Previously blocking was left
// unset here, so a transaction could never be denied unless a per-app config
// file was used.
func TestLoadConfigFromGeneralConfigPropagatesBlocking(t *testing.T) {
	gConfig = &generalConfig{
		earlyBlocking: true,
		blocking:      true,
		waceModels:    &WaceModels{},
		waceDecision:  "weighted_sum",
	}
	defer func() { gConfig = nil }()

	w := &waceWAFConfig{}
	w.LoadConfigFromGeneralConfig(*gConfig)

	if !w.blocking {
		t.Error("expected blocking to be propagated from general config, got false")
	}
	if !w.earlyBlocking {
		t.Error("expected earlyBlocking to be propagated from general config, got false")
	}
	if !reflect.DeepEqual(w.waceDecisionIds, []string{"weighted_sum"}) {
		t.Errorf("expected waceDecisionIds %q, got %q", []string{"weighted_sum"}, w.waceDecisionIds)
	}
}

// TestNewWAFDisableCRS verifies that setting disable_crs in the per-app
// config skips injecting the CRS-specific directives (getConfigRules), even
// though a crs_version is configured in the general config. The CRS ruleset
// itself is intentionally not loaded here: if disable_crs were ignored,
// WAF creation would fail because the injected SecRuleUpdateActionById
// directives reference CRS rule ids that don't exist.
func TestNewWAFDisableCRS(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig().
		WithDirectivesFromFile("testdata/config/disablecrswaceappconfig.yaml")
	_, err := NewWAF(wafConfig)
	if err != nil {
		t.Fatalf("expected WAF creation to succeed with disable_crs set, got: %v", err)
	}
}

// TestNewWAFCRSRequiredWithoutDisableCRS is the counterpart to
// TestNewWAFDisableCRS: without disable_crs, getConfigRules still injects the
// CRS-specific directives, so creating a WAF without the CRS ruleset loaded
// must fail. This proves TestNewWAFDisableCRS passes because of disable_crs,
// not because the directives are always skipped.
func TestNewWAFCRSRequiredWithoutDisableCRS(t *testing.T) {
	configFilePath = "testdata/config/waceconfig.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig().
		WithDirectivesFromFile("testdata/config/app1waceappconfig.yaml")
	_, err := NewWAF(wafConfig)
	if err == nil {
		t.Fatal("expected WAF creation to fail: crs_version is configured but the CRS ruleset was never loaded")
	}
}

func TestNewWaceDefaultModelsConfig(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
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
		t.Errorf("Error loading config: %s", err.Error())
	}

	expected := &WaceModels{
		reqHeadModelIDs:  []string{"trivialRequestHeaders"},
		reqBodyModelIDs:  []string{"trivialRequestBody"},
		reqModelIDs:      []string{"trivialAllRequest"},
		respHeadModelIDs: []string{"trivialResponseHeaders"},
		respBodyModelIDs: []string{"trivialResponseBody"},
		respModelIDs:     []string{"trivialAllResponse"},
	}

	if !reflect.DeepEqual(gConfig.waceModels, expected) {
		t.Errorf("Error: models do not match expected %v, got %v", expected, gConfig.waceModels)
	}

	models := []string{
		"trivialRequestHeaders",
		"trivialRequestBody",
		"trivialAllRequest",
		"trivialResponseHeaders",
		"trivialResponseBody",
		"trivialAllResponse",
	}
	results, decisionIds, err := newWacePluginsConfig(models, []string{"weighted_sum"})

	if err != nil {
		t.Errorf("Error creating new models config: %s", err.Error())
	}

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("Error: models do not match expected %v, got %v", expected, results)
	}

	expectedDecisionIds := []string{"weighted_sum"}
	if !reflect.DeepEqual(decisionIds, expectedDecisionIds) {
		t.Errorf("Error: decision ids do not match expected %v, got %v", expectedDecisionIds, decisionIds)
	}
}

func TestGeneralConfigLoadConfigTrainingFields(t *testing.T) {
	gCfg := generalConfig{}
	config := []byte(`
logpath: "/dev/null"
loglevel: "WARN"
modelplugins:
  - id: "model_training"
    plugintype: RequestHeaders
    path: "testdata/plugins/trivial.so"
    weight: 0.25
    training: true
    training_data:
      max_samples: 50
      result_file_path: "/tmp/training_results.json"
decisionplugins:
  - id: "weighted_sum"
    path: "testdata/plugins/weighted_sum.so"
options:
  crs_version: "4.4.0-dev"
ruleidsforexceptions:
  RequestHeaders: 100`)

	confData, err := gCfg.LoadConfig(config)
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	if len(confData.Modelplugins) == 0 {
		t.Fatal("no model plugins in parsed config")
	}
	plugin := confData.Modelplugins[0]
	if !plugin.Training {
		t.Error("expected Training to be true")
	}
	if plugin.TrainingData.MaxSamples != 50 {
		t.Errorf("expected MaxSamples = 50, got %d", plugin.TrainingData.MaxSamples)
	}
	if plugin.TrainingData.ResultFilePath != "/tmp/training_results.json" {
		t.Errorf("expected ResultFilePath = /tmp/training_results.json, got %q", plugin.TrainingData.ResultFilePath)
	}
}

// TestNewWAFWithTrainingModel verifies that a training model, while excluded
// from the general config's default model set (getDefaultPlugins only selects
// non-training plugins, since apps that don't opt in via their own
// waceappconfig.yaml should not silently start collecting training data),
// is still loaded when an app explicitly lists it in model_ids.
func TestNewWAFWithTrainingModel(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_training_valid.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig().
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectivesFromFile("testdata/config/trainingmodelwaceappconfig.yaml")
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Fatalf("expected no error for valid training model config, got: %v", err)
	}
	if gConfig.waceModels == nil {
		t.Fatal("waceModels is nil after loading training config")
	}
	if len(gConfig.waceModels.reqHeadModelIDs) != 0 {
		t.Errorf("expected the training model to be excluded from the general config's default models, got %v", gConfig.waceModels.reqHeadModelIDs)
	}
	if len(waf.waceWafConfig.waceModels.reqHeadModelIDs) == 0 {
		t.Error("expected training model to be present in reqHeadModelIDs when opted in via the app config")
	}
}

func TestNewWAFWithInvalidTrainingConfig(t *testing.T) {
	tests := []struct {
		name       string
		configFile string
	}{
		{
			name:       "training and async are mutually exclusive",
			configFile: "testdata/config/waceconfig_training_async.yaml",
		},
		{
			name:       "training and remote are mutually exclusive",
			configFile: "testdata/config/waceconfig_training_remote.yaml",
		},
		{
			name:       "training with zero max_samples is invalid",
			configFile: "testdata/config/waceconfig_training_no_samples.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFilePath = tt.configFile
			gConfig = nil

			defer func() {
				gConfig = nil
				configstore.Clean()
			}()

			wafConfig := NewWAFConfig()
			_, err := NewWAF(wafConfig)
			if err == nil {
				t.Error("expected error but got none")
			}
		})
	}
}

func TestParseScoreParams(t *testing.T) {
	// A well-formed phase-2 reporting message as emitted (after macro
	// expansion) by the id:172 SecAction from getConfigRules. inbound_per_pl
	// is a dash-joined composite (e.g. "1-2-3-4"), not a single number, so it
	// can never be represented in the map[string]float64 result and is
	// dropped rather than surfaced as a parse error.
	report172 := "inbound_blocking=10,inbound_per_pl=1-2-3-4,SQLI=5,XSS=0,COMBINED_SCORE=15"

	tests := []struct {
		name     string
		rules    []types.MatchedRule
		phase    string
		wantOK   bool
		wantVals map[string]float64
	}{
		{
			name:   "reporting rule present as last match",
			rules:  []types.MatchedRule{matchedRule(942100, "SQL Injection Attack Detected"), matchedRule(reportingRuleIDs["2"], report172)},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]float64{
				"inbound_blocking": 10,
				"SQLI":             5, "XSS": 0, "COMBINED_SCORE": 15, "phase": 2,
			},
		},
		{
			// Regression: the reporting SecAction is not necessarily the last
			// matched rule. A later match must not shadow it; we locate it by id.
			name:   "reporting rule not last, followed by another match",
			rules:  []types.MatchedRule{matchedRule(reportingRuleIDs["2"], report172), matchedRule(949110, "Inbound Anomaly Score Exceeded")},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]float64{
				"inbound_blocking": 10,
				"SQLI":             5, "XSS": 0, "COMBINED_SCORE": 15, "phase": 2,
			},
		},
		{
			// Regression for problem #1: a disruptive rule interrupted the phase
			// before the reporting SecAction ran. The last message has no "=".
			// Old code did strings.Split(..)[1] and panicked; now we return false.
			name:   "reporting rule absent (deny short-circuited the phase)",
			rules:  []types.MatchedRule{matchedRule(200002, "Failed to parse request body.")},
			phase:  "2",
			wantOK: false,
		},
		{
			// Old code indexed rules[len-1] on an empty slice and panicked.
			name:   "no matched rules",
			rules:  []types.MatchedRule{},
			phase:  "2",
			wantOK: false,
		},
		{
			// Fragments without "=" (e.g. a stray tag) must be skipped, not panic.
			name:   "message with fragment lacking '='",
			rules:  []types.MatchedRule{matchedRule(reportingRuleIDs["2"], "inbound_blocking=10,tag:reporting,SQLI=5")},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]float64{
				"inbound_blocking": 10, "SQLI": 5, "phase": 2,
			},
		},
		{
			// Correct reporting rule is selected per phase even when several
			// reporting SecActions are present in the matched set. phaseflag is a
			// non-numeric fragment (mirroring inbound_per_pl above) and so is
			// dropped; inbound_blocking still round-trips as a float.
			name:   "picks reporting rule matching the phase",
			rules:  []types.MatchedRule{matchedRule(reportingRuleIDs["1"], "inbound_blocking=1,phaseflag=one"), matchedRule(reportingRuleIDs["2"], report172)},
			phase:  "1",
			wantOK: true,
			wantVals: map[string]float64{
				"inbound_blocking": 1, "phase": 1,
			},
		},
		{
			name:   "unknown phase",
			rules:  []types.MatchedRule{matchedRule(reportingRuleIDs["2"], report172)},
			phase:  "9",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseScoreParams(tt.rules, tt.phase)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if got != nil {
					t.Errorf("expected nil params when ok is false, got %v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, tt.wantVals) {
				t.Errorf("params mismatch:\n got:  %v\n want: %v", got, tt.wantVals)
			}
		})
	}
}

func TestConfigInterface(t *testing.T) {
	config := NewWAFConfig()
	if config == nil {
		t.Errorf("Error creating WAFConfig")
	}
	config = config.WithDirectivesFromFile("testdata/config/directives.conf").
		WithRequestBodyAccess().
		WithResponseBodyAccess().
		WithRequestBodyInMemoryLimit(2000).
		WithResponseBodyLimit(2000).
		WithRequestBodyLimit(2000).
		WithResponseBodyMimeTypes([]string{"text/html"}).
		WithDirectives("SecDefaultAction \"phase:1,nolog,auditlog,pass\"")
}
