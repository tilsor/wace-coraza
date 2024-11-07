package waceWAF

import (
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	cf "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core/configstore"
)

type generalConfig struct {
	natsURL              string
	otelURL              string
	waceModels           *WaceModels
	waceDecisions        []string
	earlyBlocking        bool
	crsVersion           string
	ruleIdsForExceptions map[string]int
}

type waceWAFConfig struct {
	coraza.WAFConfig
	exceptionsConfig      coraza.WAFConfig
	waceAppConfigFilePath string
	exceptionsFilePath    string
	waceModels            *WaceModels
	waceDecisionId        string
	earlyBlocking         bool
}

type WaceModels struct {
	reqHeadModelIDs  []string
	reqBodyModelIDs  []string
	reqModelIDs      []string
	respHeadModelIDs []string
	respBodyModelIDs []string
	respModelIDs     []string
}

type WaceGeneralConfigFileData struct {
	cf.ConfigFileData    `yaml:",inline"`
	Options              map[string]string `yaml:"options"`
	RuleIdsForExceptions map[string]int `yaml:"ruleidsforexceptions"`
}

type WaceAppConfigFileData struct {
	ModelIds   []string `yaml:"modelids"`
	DecisionId string   `yaml:"decisionid"`
	Options    map[string]string
}

// LoadConfig loads the general configuration from the config file to memory
func (g *generalConfig) LoadConfig(configFilePath string) error {
	var file, err = os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	return g.LoadGeneralConfigYaml(file)
}

func (g *generalConfig) LoadGeneralConfigYaml(config []byte) error {
	var inConf WaceGeneralConfigFileData

	err := yaml.Unmarshal(config, &inConf)
	if err != nil {
		return err
	}
	for key, value := range inConf.Options {
		fmt.Printf("key: %s, value: %s\n", key, value)
		if key == "early_blocking" {
			g.earlyBlocking = value == "true"
		} else if key == "crs_version" {
			g.crsVersion = value
		} else if key == "natsurl" {
			g.natsURL = value
		} else if key == "otelurl" {
			g.otelURL = value
		}
	}
	if g.ruleIdsForExceptions == nil {
		g.ruleIdsForExceptions = make(map[string]int)
	}
	for key, value := range inConf.RuleIdsForExceptions {
		g.ruleIdsForExceptions[key] = value
	}

	err = cf.Get().SetConfig(inConf.ConfigFileData)

	g.waceModels = NewWaceDefaultModelsConfig()
	for _, decision := range inConf.Decisionplugins {
		g.waceDecisions = append(g.waceDecisions, decision.ID)
	}

	return err
}

func (w *waceWAFConfig) LoadConfigYaml(config []byte) error {
	var inConf WaceAppConfigFileData

	err := yaml.Unmarshal(config, &inConf)
	if err != nil {
		return err
	}
	for key, value := range inConf.Options {
		if key == "early_blocking" {
			w.earlyBlocking = value == "true"
		} else if key == "appname" {
			fmt.Printf("App name: %s\n", value)
		}
	}

	w.waceModels = NewWaceModelsConfig(inConf.ModelIds)
	w.waceDecisionId = inConf.DecisionId
	fmt.Printf("Model IDs: %v\n", w.waceModels.reqHeadModelIDs)
	fmt.Printf("Decision ID: %s\n", w.waceDecisionId)
	return err
}

// LoadConfig loads the configuration from the config file to memory
func (w *waceWAFConfig) LoadConfig(configFilePath string) error {
	var file, err = os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	return w.LoadConfigYaml(file)
}

func (w *waceWAFConfig) LoadConfigFromGeneralConfig(g generalConfig) {
	w.earlyBlocking = gConfig.earlyBlocking
	w.waceModels = g.waceModels
	w.waceDecisionId = g.waceDecisions[0]
}

func NewWaceDefaultModelsConfig() *WaceModels {
	conf := cf.Get()
	reqHeadModelIDs := []string{}
	reqBodyModelIDs := []string{}
	reqModelIDs := []string{}
	respHeadModelIDs := []string{}
	respBodyModelIDs := []string{}
	respModelIDs := []string{}
	for _, model := range conf.ModelPlugins {
		if model.PluginType.String() == "RequestHeaders" {
			reqHeadModelIDs = append(reqHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "RequestBody" {
			reqBodyModelIDs = append(reqBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllRequest" {
			reqModelIDs = append(reqModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseHeaders" {
			respHeadModelIDs = append(respHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseBody" {
			respBodyModelIDs = append(respBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllResponse" {
			respModelIDs = append(respModelIDs, model.ID)
		}
	}
	return &WaceModels{reqHeadModelIDs, reqBodyModelIDs, reqModelIDs, respHeadModelIDs, respBodyModelIDs, respModelIDs}
}

func NewWaceModelsConfig(modelsIds []string) *WaceModels {
	conf := cf.Get()
	reqHeadModelIDs := []string{}
	reqBodyModelIDs := []string{}
	reqModelIDs := []string{}
	respHeadModelIDs := []string{}
	respBodyModelIDs := []string{}
	respModelIDs := []string{}
	for _, modelId := range modelsIds {
		model := conf.ModelPlugins[modelId]
		if model.PluginType.String() == "RequestHeaders" {
			reqHeadModelIDs = append(reqHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "RequestBody" {
			reqBodyModelIDs = append(reqBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllRequest" {
			reqModelIDs = append(reqModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseHeaders" {
			respHeadModelIDs = append(respHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseBody" {
			respBodyModelIDs = append(respBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllResponse" {
			respModelIDs = append(respModelIDs, model.ID)
		}
	}
	return &WaceModels{reqHeadModelIDs, reqBodyModelIDs, reqModelIDs, respHeadModelIDs, respBodyModelIDs, respModelIDs}
}

// CRSVersion can be 2, 3 or 4
func (w *waceWAFConfig) getConfigRules(CRSVersion string) []string {
	// Rule format for scores
	// inbound_blocking_anomaly_score, inbound_detection_anomaly_score, inbound_per_pl_anomaly_score, inbound_anomaly_score_threshold,
	// outbound_blocking_anomaly_score, outbound_detection_anomaly_score, outbound_per_pl_anomaly_score, outbound_anomaly_score_threshold,
	// sql_injection_score, xss_score, rfi_score, lfi_score, rce_score, php_injection_score, http_violation_score, session_fixation_score, combined_score

	res := []string{}

	switch CRSVersion[:1] {
	case "2":
		res = append(res, "SecRuleRemoveById 981175")
		res = append(res, "SecRuleRemoveById 981176")
		res = append(res, "SecRuleRemoveById 981200")
		res = append(res, "SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'175',t:none,pass,log,msg:'Inbound Attack Targeting OSVDB Flagged Resource.',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule RESOURCE:OSVDB_VULNERABLE \"@eq 1\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\"")
		res = append(res, "SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'981176',t:none,pass,log,msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule TX:ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_level}\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d+\\-/ \"(.*)\"")
		res = append(res, "SecRule TX:OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_level}\" \"chain,phase:4,id:'981200',t:none,pass,msg:'Outbound Anomaly Score Exceeded (score %{TX.OUTBOUND_ANOMALY_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}'\" \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d/ \"(.*)\"")

		// TODO: Make sense to have rules in phase 1 and 3?
		// res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		// res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		return res
	case "3":
		res = append(res, "SecRuleRemoveById 949100")
		// Review this rule
		res = append(res, "SecRule IP:REPUT_BLOCK_FLAG \"@eq 1\" \"id:100,phase:2,deny,log,msg:'Request Denied by IP Reputation Enforcement',logdata:'Previous Block Reason: %{ip.reput_block_reason}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-reputation-ip',severity:'CRITICAL',chain \n SecRule TX:DO_REPUT_BLOCK \"@eq 1\" \"setvar:'tx.inbound_anomaly_score=%{tx.anomaly_score}'")
		res = append(res, "SecRuleRemoveById 949110")
		// res = append(res, "SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, deny, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")
		res = append(res, "SecRuleRemoveById 959100")
		// res = append(res, "SecRule TX:BLOCKING_OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_threshold}\" \"id:959102, phase:4, deny, t:none, msg:'%{TX.BLOCKING_OUTBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")

		// TODO: Review presence of Combined Score
		res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		return res
	case "4":
		res = append(res, "SecRuleRemoveById 949110")
		// res = append(res, "SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, pass, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")
		res = append(res, "SecRuleRemoveById 959100")
		// res = append(res, "SecRule TX:BLOCKING_OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_threshold}\" \"id:959102, phase:4, pass, t:none, msg:'%{TX.BLOCKING_OUTBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")

		if w.earlyBlocking {
			res = append(res, "SecAction phase:1,setvar:'tx.early_blocking=1'")
		}

		res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		return res
	default:
		return []string{}
	}
}

// TODO: Check for a default value for CRS
func NewWAFConfig() coraza.WAFConfig {
	return &waceWAFConfig{coraza.NewWAFConfig(), coraza.NewWAFConfig(), "", "", nil, "", false}
}

func (conf *waceWAFConfig) WithDirectivesFromFile(filePath string) coraza.WAFConfig {
	if strings.Contains(filePath, "waceexceptions.conf") {
		conf.exceptionsFilePath = filePath
	} else if strings.Contains(filePath, "waceappconfig.yaml") {
		conf.waceAppConfigFilePath = filePath
	} else {
		conf.WAFConfig = conf.WAFConfig.WithDirectivesFromFile(filePath)
	}
	return conf
}

func (conf *waceWAFConfig) WithDirectives(directives string) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithDirectives(directives)
	return conf
}

func (conf *waceWAFConfig) WithRequestBodyAccess() coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyAccess()
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyAccess()
	return conf
}

func (conf *waceWAFConfig) WithRequestBodyLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyLimit(limit)
	return conf
}

func (conf *waceWAFConfig) WithResponseBodyAccess() coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyAccess()
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyAccess()
	return conf
}

func (conf *waceWAFConfig) WithRequestBodyInMemoryLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyInMemoryLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyInMemoryLimit(limit)
	return conf
}

func (conf *waceWAFConfig) WithResponseBodyLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyLimit(limit)
	return conf
}

func (conf *waceWAFConfig) WithResponseBodyMimeTypes(mimeTypes []string) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyMimeTypes(mimeTypes)
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyMimeTypes(mimeTypes)
	return conf
}

func (conf *waceWAFConfig) WithDebugLogger(logger debuglog.Logger) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithDebugLogger(logger)
	return conf
}

func (conf *waceWAFConfig) WithErrorCallback(logger func(rule types.MatchedRule)) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithErrorCallback(logger)
	return conf
}

func (conf *waceWAFConfig) WithRootFS(fs fs.FS) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRootFS(fs)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRootFS(fs)
	return conf
}

func (conf *waceWAFConfig) LoadExceptionsDirectives(filePath string, waceConfig *WaceModels) coraza.WAFConfig {
	finalsRules := []string{}
	modelsToSet := ""
	modelsToGet := ""
	finalRule := ""

	if len(waceConfig.reqHeadModelIDs) != 0 {
		for _, model := range waceConfig.reqHeadModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["RequestHeaders"]) + ", phase:1, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.reqBodyModelIDs) != 0 {
		for _, model := range waceConfig.reqBodyModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id" + strconv.Itoa(gConfig.ruleIdsForExceptions["RequestBody"]) + ", phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.reqModelIDs) != 0 {
		for _, model := range waceConfig.reqModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["AllRequest"]) + " phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respHeadModelIDs) != 0 {
		for _, model := range waceConfig.respHeadModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["ResponseHeaders"]) + " phase:3, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respBodyModelIDs) != 0 {
		for _, model := range waceConfig.respBodyModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["ResponseBody"]) + " phase:4, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.respModelIDs) != 0 {
		for _, model := range waceConfig.respModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["AllResponse"]) + " phase:4, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)
	}
	initialRule := "SecAction \"id:1, phase:1, nolog," + modelsToSet + " pass\""
	conf.exceptionsConfig = conf.exceptionsConfig.
		WithDirectives(initialRule).
		WithDirectivesFromFile(filePath)
	for _, rule := range finalsRules {
		conf.exceptionsConfig = conf.exceptionsConfig.WithDirectives(rule)
	}
	return conf.exceptionsConfig
}

func ParseActiveModels(exceptionRuleMessage string) []string {
	models := strings.Split(exceptionRuleMessage, ",")
	unexceptedModels := []string{}
	for _, model := range models {
		if strings.Contains(model, "true") {
			unexceptedModels = append(unexceptedModels, strings.Split(model, ":")[0])
		}
	}
	return unexceptedModels
}
