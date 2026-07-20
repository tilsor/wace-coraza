package waceWAF

import (
	"os"
	"reflect"
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
	// Get rules for CRS Version 2
	waceWAFConfig := waceWAFConfig{earlyBlocking: false}
	configRules := waceWAFConfig.getConfigRules("2.2")

	expectedRules := []string{
		"SecRuleRemoveById 981175",
		"SecRuleRemoveById 981176",
		"SecRuleRemoveById 981200",
		"SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'175',t:none,pass,log,msg:'Inbound Attack Targeting OSVDB Flagged Resource.',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule RESOURCE:OSVDB_VULNERABLE \"@eq 1\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\"",
		"SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'981176',t:none,pass,log,msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule TX:ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_level}\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d+\\-/ \"(.*)\"",
		"SecRule TX:OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_level}\" \"chain,phase:4,id:'981200',t:none,pass,msg:'Outbound Anomaly Score Exceeded (score %{TX.OUTBOUND_ANOMALY_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}'\" \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d/ \"(.*)\"",
		"SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting',severity:'NOTICE'\"",
	}

	for i, rule := range configRules {
		if rule != expectedRules[i] {
			t.Errorf("Error getting rules: Expected: %s, Got: %s", expectedRules[i], rule)
		}
	}

	// Get rules for CRS Version 3
	configRules = waceWAFConfig.getConfigRules("3.3")
	// TODO: Review presence of Combined Score
	expectedRules = []string{
		"SecRuleRemoveById 949100",
		"SecRule IP:REPUT_BLOCK_FLAG \"@eq 1\" \"id:100,phase:2,deny,log,msg:'Request Denied by IP Reputation Enforcement',logdata:'Previous Block Reason: %{ip.reput_block_reason}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-reputation-ip',severity:'CRITICAL',chain \n SecRule TX:DO_REPUT_BLOCK \"@eq 1\" \"setvar:'tx.inbound_anomaly_score=%{tx.anomaly_score}'",
		"SecRuleRemoveById 949110",
		"SecRuleRemoveById 959100",
		"SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
	}

	for i, rule := range configRules {
		if rule != expectedRules[i] {
			t.Errorf("Error getting rules: Expected: %s, Got: %s", expectedRules[i], rule)
		}
	}

	// Get rules for CRS Version 4
	configRules = waceWAFConfig.getConfigRules("4.4")

	expectedRules = []string{
		"SecRuleRemoveById 949110",
		"SecRuleRemoveById 959100",
		"SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
		"SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"",
	}

	for i, rule := range configRules {
		if rule != expectedRules[i] {
			t.Errorf("Error getting rules: Expected: %s, Got: %s", expectedRules[i], rule)
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

	wafConfig := NewWAFConfig()
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err)
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

	wafConfig := NewWAFConfig()
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

	if wConfig.waceDecisionId == "" {
		t.Error("Decision Plugin Id was not loaded properly")
	}

	if len(wConfig.waceModels.reqHeadModelIDs) == 0 {
		t.Errorf("Model Plugin Ids were not loaded properly, expected %d model Id, got %d", 1, len(wConfig.waceModels.reqHeadModelIDs))
	}
}

func TestNewWaceDefaultModelsConfig(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_all_models.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig()
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
	results, err := NewWaceModelsConfig(models)

	if err != nil {
		t.Errorf("Error creating new models config: %s", err.Error())
	}

	if !reflect.DeepEqual(results, expected) {
		t.Errorf("Error: models do not match expected %v, got %v", expected, results)
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

func TestNewWAFWithTrainingModel(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_training_valid.yaml"
	gConfig = nil

	defer func() {
		gConfig = nil
		configstore.Clean()
	}()

	wafConfig := NewWAFConfig()
	_, err := NewWAF(wafConfig)
	if err != nil {
		t.Fatalf("expected no error for valid training model config, got: %v", err)
	}
	if gConfig.waceModels == nil {
		t.Fatal("waceModels is nil after loading training config")
	}
	if len(gConfig.waceModels.reqHeadModelIDs) == 0 {
		t.Error("expected training model to be present in reqHeadModelIDs")
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
	// expansion) by the id:172 SecAction from getConfigRules.
	report172 := "inbound_blocking=10,inbound_per_pl=1-2-3-4,SQLI=5,XSS=0,COMBINED_SCORE=15"

	tests := []struct {
		name     string
		rules    []types.MatchedRule
		phase    string
		wantOK   bool
		wantVals map[string]string
	}{
		{
			name:   "reporting rule present as last match",
			rules:  []types.MatchedRule{matchedRule(942100, "SQL Injection Attack Detected"), matchedRule(172, report172)},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]string{
				"inbound_blocking": "10", "inbound_per_pl": "1-2-3-4",
				"SQLI": "5", "XSS": "0", "COMBINED_SCORE": "15", "phase": "2",
			},
		},
		{
			// Regression: the reporting SecAction is not necessarily the last
			// matched rule. A later match must not shadow it; we locate it by id.
			name:   "reporting rule not last, followed by another match",
			rules:  []types.MatchedRule{matchedRule(172, report172), matchedRule(949110, "Inbound Anomaly Score Exceeded")},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]string{
				"inbound_blocking": "10", "inbound_per_pl": "1-2-3-4",
				"SQLI": "5", "XSS": "0", "COMBINED_SCORE": "15", "phase": "2",
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
			rules:  []types.MatchedRule{matchedRule(172, "inbound_blocking=10,tag:reporting,SQLI=5")},
			phase:  "2",
			wantOK: true,
			wantVals: map[string]string{
				"inbound_blocking": "10", "SQLI": "5", "phase": "2",
			},
		},
		{
			// Correct reporting rule is selected per phase even when several
			// reporting SecActions are present in the matched set.
			name:   "picks reporting rule matching the phase",
			rules:  []types.MatchedRule{matchedRule(171, "inbound_blocking=1,phaseflag=one"), matchedRule(172, report172)},
			phase:  "1",
			wantOK: true,
			wantVals: map[string]string{
				"inbound_blocking": "1", "phaseflag": "one", "phase": "1",
			},
		},
		{
			name:   "unknown phase",
			rules:  []types.MatchedRule{matchedRule(172, report172)},
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
