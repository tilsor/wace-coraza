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
	blocking             bool
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
	disableCRS            bool
	blocking              bool
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
	cf.ConfigFileData `yaml:",inline"`
	EarlyBlocking     bool           `yaml:"early_blocking"`
	CRSVersion        string         `yaml:"crs_version"`
	Blocking          bool           `yaml:"blocking"`
	OtelURL           string         `yaml:"otel_url"`
	ExceptionIDs      map[string]int `yaml:"exception_ids"`
}

// WaceAppConfigFileData holds the application configuration data from the config file
type WaceAppConfigFileData struct {
	ModelIds      []string `yaml:"modelids"`
	DecisionId    string   `yaml:"decisionid"`
	EarlyBlocking bool     `yaml:"early_blocking"`
	DisableCRS    bool     `yaml:"disable_crs"`
	Blocking      bool     `yaml:"blocking"`
	AppName       string   `yaml:"app_name"`
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
	g.earlyBlocking = confData.EarlyBlocking
	g.crsVersion = confData.CRSVersion
	g.blocking = confData.Blocking
	g.otelURL = confData.OtelURL
	if g.ruleIdsForExceptions == nil {
		g.ruleIdsForExceptions = make(map[string]int)
	}
	for key, value := range confData.ExceptionIDs {
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

	w.disableCRS = conf.DisableCRS
	w.earlyBlocking = conf.EarlyBlocking
	w.blocking = conf.Blocking

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
	w.blocking = g.blocking
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

// reportingMsgTemplate is the msg of the SecAction that reports, per phase,
// the anomaly scores computed by CRS so the WACE decision plugin can read
// them back out of the matched rule (see parseScoreParams). The content is
// identical for every phase; only the rule id and phase differ.
const reportingMsgTemplate = "inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}"

// reportingRule builds the SecAction that reports the CRS anomaly scores for
// the given phase, using the id assigned to that phase in reportingRuleIDs.
func reportingRule(phase int) string {
	id := reportingRuleIDs[strconv.Itoa(phase)]
	return fmt.Sprintf("SecAction \"id:%d,phase:%d,pass,t:none,noauditlog,msg:'%s',tag:'reporting',severity:'NOTICE'\"", id, phase, reportingMsgTemplate)
}

// getConfigRules returns the WACE directives injected around the OWASP CRS
// rules.
func (w *waceWAFConfig) getConfigRules(CRSVersion string) []string {
	if CRSVersion == "" {
		return []string{}
	}

	res := []string{}

	res = append(res, "SecRuleUpdateActionById 949111 \"pass\"")
	res = append(res, "SecRuleUpdateActionById 949110 \"pass\"")
	res = append(res, "SecRuleUpdateActionById 959101 \"pass\"")
	res = append(res, "SecRuleUpdateActionById 959100 \"pass\"")

	if w.earlyBlocking {
		res = append(res, "SecAction \"id:9011150,phase:1,setvar:'tx.early_blocking=1'\"")
	}

	for phase := 1; phase <= 4; phase++ {
		res = append(res, reportingRule(phase))
	}

	return res
}

// NewWAFConfig creates a new WAFConfig with default values
func NewWAFConfig() coraza.WAFConfig {
	return &waceWAFConfig{coraza.NewWAFConfig(), coraza.NewWAFConfig(), "", "", nil, "", false, false, false}
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
	"1": 9491110,
	"2": 9491100,
	"3": 9591010,
	"4": 9591000,
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
