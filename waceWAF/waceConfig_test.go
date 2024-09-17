package waceWAF

import (
	"testing"
)

func TestNewWaceConfig(t *testing.T) {
	wafConfig := NewWAFConfig()
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err)
	}
	conf := waf.waceConfig
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
	models := ParseExceptedModels(exceptionRuleMessage)
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