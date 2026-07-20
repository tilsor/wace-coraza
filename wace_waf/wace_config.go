package waceWAF

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	cf "github.com/tilsor/ModSecIntl_wace_lib/configstore"
)

// generalConfig is the struct that holds the general configuration of the WAF
type generalConfig struct {
	otelURL              string
	waceModels           *WaceModels
	waceDecisions        []string
	earlyBlocking        bool
	crsVersion           string
	ruleIdsForExceptions map[string]int
	hash                 string
}

// waceWAFConfig implements the WAFConfig interface and adds the specific configuration for the WaceWAF
type waceWAFConfig struct {
	coraza.WAFConfig
	exceptionsConfig      coraza.WAFConfig
	waceAppConfigFilePath string
	exceptionsFilePath    string
	waceModels            *WaceModels
	waceDecisionId        string
	earlyBlocking         bool
}

// WaceModels holds the model ids for the different types of models
type WaceModels struct {
	reqHeadModelIDs  []string
	reqBodyModelIDs  []string
	reqModelIDs      []string
	respHeadModelIDs []string
	respBodyModelIDs []string
	respModelIDs     []string
}

// waceGeneralConfigFileData holds the general configuration data from the config file
type waceGeneralConfigFileData struct {
	cf.ConfigFileData    `yaml:",inline"`
	Options              map[string]string `yaml:"options"`
	RuleIdsForExceptions map[string]int    `yaml:"ruleidsforexceptions"`
}

// WaceAppConfigFileData holds the application configuration data from the config file
type WaceAppConfigFileData struct {
	ModelIds   []string `yaml:"modelids"`
	DecisionId string   `yaml:"decisionid"`
	Options    map[string]string
}

func dataHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// LoadConfig loads the general configuration from the config file to memory
func (g *generalConfig) LoadConfig(config []byte) (waceGeneralConfigFileData, error) {
	var confData waceGeneralConfigFileData

	err := yaml.Unmarshal(config, &confData)
	if err != nil {
		return waceGeneralConfigFileData{}, err
	}
	for key, value := range confData.Options {
		if key == "early_blocking" {
			g.earlyBlocking = value == "true"
		} else if key == "crs_version" {
			g.crsVersion = value
		} else if key == "otelurl" {
			g.otelURL = value
		}
	}
	if g.ruleIdsForExceptions == nil {
		g.ruleIdsForExceptions = make(map[string]int)
	}
	for key, value := range confData.RuleIdsForExceptions {
		g.ruleIdsForExceptions[key] = value
	}

	return confData, err
}

// LoadConfigYaml loads the application configuration from the config file to memory
func (w *waceWAFConfig) LoadConfigYaml(config []byte) error {
	var conf WaceAppConfigFileData

	err := yaml.Unmarshal(config, &conf)
	if err != nil {
		return err
	}
	for key, value := range conf.Options {
		if key == "early_blocking" {
			w.earlyBlocking = value == "true"
		}
	}

	w.waceModels, err = NewWaceModelsConfig(conf.ModelIds)
	if err != nil {
		return err
	}
	if slices.Contains(gConfig.waceDecisions, conf.DecisionId) {
		w.waceDecisionId = conf.DecisionId
	} else {
		return fmt.Errorf("Decision id %s does not exist in general configuration file or it wasn't loaded properly", conf.DecisionId)
	}

	return nil
}

// LoadConfig loads the configuration from the config file to memory
func (w *waceWAFConfig) LoadConfig(configFilePath string) error {
	var file, err = os.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	return w.LoadConfigYaml(file)
}

// LoadConfigFromGeneralConfig loads the application configuration from the general configuration
// it is used when the application configuration is not provided in a file.
// It uses the first decision plugin and uses all the models declared in the general configuration
func (w *waceWAFConfig) LoadConfigFromGeneralConfig(g generalConfig) {
	w.earlyBlocking = gConfig.earlyBlocking
	w.waceModels = g.waceModels
	w.waceDecisionId = g.waceDecisions[0]
}

// getDefaultPlugins gets the list of plugin IDs from WACE ConfigStore after they were validated
func getDefaultPlugins() (*WaceModels, map[string]struct{}, error) {
	cs, err := cf.Get()
	if err != nil {
		return &WaceModels{}, nil, err
	}
	models := &WaceModels{}
	models.reqHeadModelIDs = []string{}
	models.reqBodyModelIDs = []string{}
	models.reqModelIDs = []string{}
	models.respHeadModelIDs = []string{}
	models.respBodyModelIDs = []string{}
	models.respModelIDs = []string{}
	for _, model := range cs.ModelPlugins {
		switch model.PluginType {
		case cf.RequestHeaders:
			models.reqHeadModelIDs = append(models.reqHeadModelIDs, model.ID)
		case cf.RequestBody:
			models.reqBodyModelIDs = append(models.reqBodyModelIDs, model.ID)
		case cf.AllRequest:
			models.reqModelIDs = append(models.reqModelIDs, model.ID)
		case cf.ResponseHeaders:
			models.respHeadModelIDs = append(models.respHeadModelIDs, model.ID)
		case cf.ResponseBody:
			models.respBodyModelIDs = append(models.respBodyModelIDs, model.ID)
		case cf.AllResponse:
			models.respModelIDs = append(models.respModelIDs, model.ID)
		}
	}

	decisionIDs := make(map[string]struct{})
	for id := range cs.DecisionPlugins {
		decisionIDs[id] = struct{}{}
	}

	return models, decisionIDs, nil
}

func (g *generalConfig) setDefaultPlugins(loadedConf waceGeneralConfigFileData) error {
	models, decisions, err := getDefaultPlugins()
	if err != nil {
		return err
	}

	g.waceModels = models

	if len(decisions) == 0 {
		return fmt.Errorf("There are no decision plugins available")
	}

	for _, decisionPlugin := range loadedConf.Decisionplugins {
		if _, ok := decisions[decisionPlugin.ID]; ok {
			g.waceDecisions = append(g.waceDecisions, decisionPlugin.ID)
		}
	}

	return nil
}

// NewWaceModelsConfig creates a new WaceModels with the models with the given ids
// using the models stored in the WACE ConfigStore
func NewWaceModelsConfig(modelsIds []string) (*WaceModels, error) {
	cs, err := cf.Get()
	if err != nil {
		return &WaceModels{}, err
	}
	models := &WaceModels{}
	models.reqHeadModelIDs = []string{}
	models.reqBodyModelIDs = []string{}
	models.reqModelIDs = []string{}
	models.respHeadModelIDs = []string{}
	models.respBodyModelIDs = []string{}
	models.respModelIDs = []string{}
	for _, model := range cs.ModelPlugins {
		switch model.PluginType {
		case cf.RequestHeaders:
			models.reqHeadModelIDs = append(models.reqHeadModelIDs, model.ID)
		case cf.RequestBody:
			models.reqBodyModelIDs = append(models.reqBodyModelIDs, model.ID)
		case cf.AllRequest:
			models.reqModelIDs = append(models.reqModelIDs, model.ID)
		case cf.ResponseHeaders:
			models.respHeadModelIDs = append(models.respHeadModelIDs, model.ID)
		case cf.ResponseBody:
			models.respBodyModelIDs = append(models.respBodyModelIDs, model.ID)
		case cf.AllResponse:
			models.respModelIDs = append(models.respModelIDs, model.ID)
		}
	}
	return models, nil
}

// getConfigRules returns the rules that are specific to the CRS version
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

		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting',severity:'NOTICE'\"")
		return res
	case "3":
		res = append(res, "SecRuleRemoveById 949100")
		// Review this rule
		res = append(res, "SecRule IP:REPUT_BLOCK_FLAG \"@eq 1\" \"id:100,phase:2,deny,log,msg:'Request Denied by IP Reputation Enforcement',logdata:'Previous Block Reason: %{ip.reput_block_reason}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-reputation-ip',severity:'CRITICAL',chain \n SecRule TX:DO_REPUT_BLOCK \"@eq 1\" \"setvar:'tx.inbound_anomaly_score=%{tx.anomaly_score}'")
		res = append(res, "SecRuleRemoveById 949110")
		res = append(res, "SecRuleRemoveById 959100")

		// TODO: Review presence of Combined Score
		res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting',severity:'NOTICE'\"")
		return res
	case "4":
		res = append(res, "SecRuleRemoveById 949110")
		res = append(res, "SecRuleRemoveById 959100")

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

// NewWAFConfig creates a new WAFConfig with default values
func NewWAFConfig() coraza.WAFConfig {
	return &waceWAFConfig{coraza.NewWAFConfig(), coraza.NewWAFConfig(), "", "", nil, "", false}
}

// WithDirectivesFromFile implements the function specified in the WAFConfig interface to add directives from a file
// if the file is the exceptions file, it is added to the exceptionsConfig
// if the file is the waceAppConfig file, it is added to the waceAppConfigFilePath
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

// WithDirectives implements the function specified in the WAFConfig interface to add directives
func (conf *waceWAFConfig) WithDirectives(directives string) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithDirectives(directives)
	return conf
}

// WithRequestHeadersAccess implements the function specified in the WAFConfig interface to add request headers access
func (conf *waceWAFConfig) WithRequestBodyAccess() coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyAccess()
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyAccess()
	return conf
}

// WithRequestBodyLimit implements the function specified in the WAFConfig interface to add request body limit
func (conf *waceWAFConfig) WithRequestBodyLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyLimit(limit)
	return conf
}

// WithResponseBodyAccess implements the function specified in the WAFConfig interface to add response body access
func (conf *waceWAFConfig) WithResponseBodyAccess() coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyAccess()
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyAccess()
	return conf
}

// WithRequestBodyInMemoryLimit implements the function specified in the WAFConfig interface to add request body in memory limit
func (conf *waceWAFConfig) WithRequestBodyInMemoryLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRequestBodyInMemoryLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRequestBodyInMemoryLimit(limit)
	return conf
}

// WithResponseBodyLimit implements the function specified in the WAFConfig interface to add response body limit
func (conf *waceWAFConfig) WithResponseBodyLimit(limit int) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyLimit(limit)
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyLimit(limit)
	return conf
}

// WithResponseBodyMimeTypes implements the function specified in the WAFConfig interface to add response body mime types
func (conf *waceWAFConfig) WithResponseBodyMimeTypes(mimeTypes []string) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithResponseBodyMimeTypes(mimeTypes)
	conf.exceptionsConfig = conf.exceptionsConfig.WithResponseBodyMimeTypes(mimeTypes)
	return conf
}

// WithDebugLogger implements the function specified in the WAFConfig interface to add a debug logger
func (conf *waceWAFConfig) WithDebugLogger(logger debuglog.Logger) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithDebugLogger(logger)
	return conf
}

// WithErrorCallback implements the function specified in the WAFConfig interface to add an error callback
func (conf *waceWAFConfig) WithErrorCallback(logger func(rule types.MatchedRule)) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithErrorCallback(logger)
	return conf
}

// WithRootFS implements the function specified in the WAFConfig interface to add the root file system
func (conf *waceWAFConfig) WithRootFS(fs fs.FS) coraza.WAFConfig {
	conf.WAFConfig = conf.WAFConfig.WithRootFS(fs)
	conf.exceptionsConfig = conf.exceptionsConfig.WithRootFS(fs)
	return conf
}

// LoadExceptionsDirectives loads the exceptions directives from the exceptions file
// previously sets the models in seclang variables and then adds the exceptions directives
// finally adds a final rule to export the active models
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
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["RequestBody"]) + ", phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.reqModelIDs) != 0 {
		for _, model := range waceConfig.reqModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["AllRequest"]) + ", phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respHeadModelIDs) != 0 {
		for _, model := range waceConfig.respHeadModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["ResponseHeaders"]) + ", phase:3, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respBodyModelIDs) != 0 {
		for _, model := range waceConfig.respBodyModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["ResponseBody"]) + ", phase:4, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.respModelIDs) != 0 {
		for _, model := range waceConfig.respModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:" + strconv.Itoa(gConfig.ruleIdsForExceptions["AllResponse"]) + ", phase:4, nolog, msg:'" + modelsToGet + "', pass\""
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

// reportingRuleIDs maps the processing phase (as used in wafParams) to the id
// of the reporting SecAction that logs the anomaly scores. These ids must match
// the SecAction directives injected by getConfigRules.
var reportingRuleIDs = map[string]int{
	"1": 171,
	"2": 172,
	"3": 173,
	"4": 174,
}

// parseScoreParams locates the WACE reporting rule for the given phase among the
// matched rules and parses its message into the score parameters passed to the
// decision plugin. The matched rules are scanned in reverse because the reporting
// SecAction is normally the last rule to match in its phase, but this does not
// rely on it being last: it matches explicitly by rule id.
//
// It returns ok == false when the reporting rule is not present. That happens
// when a disruptive (deny) rule short-circuited the phase before the reporting
// SecAction could run, in which case Coraza is already blocking the transaction
// and there is nothing for WACE to evaluate.
func parseScoreParams(rules []types.MatchedRule, phase string) (map[string]string, bool) {
	reportID, ok := reportingRuleIDs[phase]
	if !ok {
		return nil, false
	}

	for i := len(rules) - 1; i >= 0; i-- {
		if rules[i].Rule().ID() != reportID {
			continue
		}

		wafParams := map[string]string{}
		for _, score := range strings.Split(rules[i].Message(), ",") {
			key, value, found := strings.Cut(score, "=")
			if !found {
				continue
			}
			wafParams[key] = value
		}
		wafParams["phase"] = phase
		return wafParams, true
	}

	return nil, false
}

// ParseActiveModels parses the exception rule message to get the active models
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
