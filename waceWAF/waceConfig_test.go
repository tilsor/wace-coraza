package waceWAF

import (
	"reflect"
	"testing"
	// wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"
	// cf "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core/configstore"
)

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

func TestNewWaceConfig(t *testing.T) {
	wafConfig := NewWAFConfig()
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err)
	}
	conf := waf.waceWafConfig.waceModels
	if conf == nil {
		t.Errorf("Error creating WaceConfig")
	}
	if len(conf.reqHeadModelIDs) == 0 {
		t.Errorf("Error creating WaceConfig: reqHeadModelIDs is empty")
	}
	if (conf.reqHeadModelIDs[0] != "trivial" && conf.reqHeadModelIDs[1] != "trivial") {
		t.Errorf("Error creating WaceConfig: first model is not 'trivial'")
	}
}

func TestParseUnexceptedModels(t *testing.T){
	exceptionRuleMessage := "model1:true,model2:false,model3:true,"
	models := ParseActiveModels(exceptionRuleMessage)
	if len(models) != 2 {
		t.Errorf("Error parsing unexcepted models: Expected 2, Got %d", len(models))
	}
	if (models[0] != "model1" && models[1] != "model1") {
		t.Errorf("Error parsing unexcepted models: Expected 'model1', Got %s and %s", models[0], models[1])
	}
	if (models[0] != "model3" && models[1] != "model3") {
		t.Errorf("Error parsing unexcepted models: Expected 'model3', Got %s and %s", models[0], models[1])
	}
}

func TestGeneralConfigLoadConfig(t *testing.T) {
	gConfig := generalConfig{}
	configFilePath := "../../caddy_wace/waceconfig.yaml" // Ruta al archivo de configuración general

	err := gConfig.LoadConfig(configFilePath)
	if err != nil {
		t.Fatalf("Error al cargar configuración general: %v", err)
	}

	if gConfig.crsVersion == "" {
		t.Error("crsVersion debería estar configurado")
	}
}

// Ejemplo de prueba para waceWAFConfig.LoadConfig
func TestWaceWAFConfigLoadConfig(t *testing.T) {
	wConfig := waceWAFConfig{}
	configFilePath := "../../caddy_wace/app1waceappconfig.yaml" // Ruta al archivo de configuración de la aplicación

	err := wConfig.LoadConfig(configFilePath)
	if err != nil {
		t.Fatalf("Error al cargar configuración de WAF: %v", err)
	}

	// Verifica algunos valores de configuración cargados
	if wConfig.waceDecisionId == "" {
		t.Error("waceDecisionId debería estar configurado")
	}

	if len(wConfig.waceModels.reqHeadModelIDs) == 0 {
		t.Error("reqHeadModelIDs debería tener al menos un valor")
	}
}

// Ejemplo de prueba para waceWAFConfig.LoadConfigFromGeneralConfig
func TestLoadConfigFromGeneralConfig(t *testing.T) {
	gConfig := generalConfig{
		otelURL:       "http://localhost:4317",
		waceDecisions: []string{"decision1"},
		earlyBlocking: false,
		waceModels:    &WaceModels{reqHeadModelIDs: []string{"model1"}},
	}

	wConfig := waceWAFConfig{}
	wConfig.LoadConfigFromGeneralConfig(gConfig)

	if wConfig.waceDecisionId != gConfig.waceDecisions[0] {
		t.Errorf("Esperaba waceDecisionId %v, obtuvo %v", gConfig.waceDecisions[0], wConfig.waceDecisionId)
	}

	if wConfig.earlyBlocking != gConfig.earlyBlocking {
		t.Errorf("Esperaba earlyBlocking %v, obtuvo %v", gConfig.earlyBlocking, wConfig.earlyBlocking)
	}
}


func TestNewWaceDefaultModelsConfig(t *testing.T) {
	result := NewWaceDefaultModelsConfig()

	expected := &WaceModels{
		reqHeadModelIDs:  []string{"trivial", "trivial2"},
		reqBodyModelIDs:  []string{},
		reqModelIDs:      []string{},
		respHeadModelIDs: []string{},
		respBodyModelIDs: []string{},
		respModelIDs:     []string{},
	}

	if !reflect.DeepEqual(result, expected) {
		t.Errorf("NewWaceDefaultModelsConfig() = %v; expected %v", result, expected)
	}
}

// func TestWithDirectivesFromFile(t *testing.T) {
// 	wafConfig := waceWAFConfig{}
// 	wafConfig.WithDirectivesFromFile("../coraza.conf")
// 	wafConfig.WithDirectivesFromFile("../coreruleset/crs-setup.conf.example")
// 	wafConfig.WithDirectivesFromFile("../coreruleset/rules/*.conf")
// 	wafConfig.WithDirectivesFromFile("../waceexceptions.conf")
// 	wafConfig.WithDirectivesFromFile("waceconfig.yaml")

// 	if len(wafConfig.waceModels.reqHeadModelIDs) != 2 {
// 		t.Errorf("Error adding directives: Expected 2, Got %d", len(wafConfig.waceModels.reqHeadModelIDs))
// 	}
// }