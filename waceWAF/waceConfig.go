package waceWAF

import (
	"io/fs"
	"strings"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"
	cf "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core/configstore"
)

type waceWAFConfig struct {
	coraza.WAFConfig
	wantExceptions   bool
	exceptionsConfig coraza.WAFConfig
}

type WaceConfig struct {
	reqHeadModelIDs  []string
	reqBodyModelIDs  []string
	reqModelIDs      []string
	respHeadModelIDs []string
	respBodyModelIDs []string
	respModelIDs     []string
}

func NewWaceConfig() *WaceConfig {
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
	return &WaceConfig{reqHeadModelIDs, reqBodyModelIDs, reqModelIDs, respHeadModelIDs, respBodyModelIDs, respModelIDs}
}

func NewWAFConfig() coraza.WAFConfig {
	return &waceWAFConfig{coraza.NewWAFConfig(), false, coraza.NewWAFConfig()}
}

func (conf *waceWAFConfig) WithDirectivesFromFile(filePath string) coraza.WAFConfig {
	if filePath == "exceptions.conf" {
		conf.wantExceptions = true
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

func (conf *waceWAFConfig) LoadExceptionsDirectives(filePath string, waceConfig *WaceConfig) coraza.WAFConfig {
	finalsRules := []string{}
	modelsToSet := ""
	modelsToGet := ""
	finalRule := ""

	if len(waceConfig.reqHeadModelIDs) != 0 {
		for _, model := range waceConfig.reqHeadModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:100, phase:1, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.reqBodyModelIDs) != 0 {
		for _, model := range waceConfig.reqBodyModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}		
		finalRule = "SecAction \"id:200, phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.reqModelIDs) != 0	{
		for _, model := range waceConfig.reqModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:300, phase:2, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respHeadModelIDs) != 0 {
		for _, model := range waceConfig.respHeadModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:400, phase:3, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}

	if len(waceConfig.respBodyModelIDs) != 0 {
		for _, model := range waceConfig.respBodyModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:500, phase:4, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)

		modelsToGet = ""
	}
	if len(waceConfig.respModelIDs) != 0  {
		for _, model := range waceConfig.respModelIDs {
			modelsToSet += "setvar:tx." + model + "=true,"
			modelsToGet += model + ":%{tx." + model + "},"
		}
		finalRule = "SecAction \"id:600, phase:4, nolog, msg:'" + modelsToGet + "', pass\""
		finalsRules = append(finalsRules, finalRule)
	}

	initialRule := "SecAction \"id:1, phase:1, nolog," + modelsToSet + " pass\""
	conf.exceptionsConfig = conf.exceptionsConfig.
		WithDirectives(initialRule).
		WithDirectivesFromFile("exceptions.conf")
	for _, rule := range finalsRules {
		conf.exceptionsConfig = conf.exceptionsConfig.WithDirectives(rule)
	}
	return conf.exceptionsConfig
}

func ParseExceptedModels(exceptionRuleMessage string) []string {
	models := strings.Split(exceptionRuleMessage, ",")
	unexceptedModels := []string{}
	for _, model := range models {
		if strings.Contains(model, "true") {
			unexceptedModels = append(unexceptedModels, strings.Split(model, ":")[0])
		}
	}
	return unexceptedModels
}