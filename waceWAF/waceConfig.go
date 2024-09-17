package waceWAF

import (
	cf "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core/configstore"
)

type WaceConfig struct {
	reqHeadModelIDs  []string
	reqBodyModelIDs  []string
	reqModelIDs      []string
	respHeadModelIDs []string
	respBodyModelIDs []string
	respModelIDs     []string
}

func NewWaceConfig() *WaceConfig {
	conf:= cf.Get()
	reqHeadModelIDs := []string{}
	reqBodyModelIDs := []string{}
	reqModelIDs := []string{}
	respHeadModelIDs := []string{}
	respBodyModelIDs := []string{}
	respModelIDs := []string{}
	for _, model := range conf.ModelPlugins{
		if model.PluginType.String() == "RequestHeaders"{
			reqHeadModelIDs = append(reqHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "RequestBody"{
			reqBodyModelIDs = append(reqBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllRequest"{
			reqModelIDs = append(reqModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseHeaders"{
			respHeadModelIDs = append(respHeadModelIDs, model.ID)
		} else if model.PluginType.String() == "ResponseBody"{
			respBodyModelIDs = append(respBodyModelIDs, model.ID)
		} else if model.PluginType.String() == "AllResponse"{
			respModelIDs = append(respModelIDs, model.ID)
		}
	}
	return &WaceConfig{reqHeadModelIDs, reqBodyModelIDs, reqModelIDs, respHeadModelIDs, respBodyModelIDs, respModelIDs}
}

// CRSVersion can be 2, 3 or 4
func getConfigRules(CRSVersion string) []string {
	// Rule format for scores
	// TODO: Review the posibility of adding custom format for the scores
		// inbound_blocking_anomaly_score, inbound_detection_anomaly_score, inbound_per_pl_anomaly_score, inbound_anomaly_score_threshold,
		// outbound_blocking_anomaly_score, outbound_detection_anomaly_score, outbound_per_pl_anomaly_score, outbound_anomaly_score_threshold,
		// sql_injection_score, xss_score, rfi_score, lfi_score, rce_score, php_injection_score, http_violation_score, session_fixation_score, combined_score

	res := []string{}


	switch CRSVersion[:1] {
	case "2":
		res = append(res, "SecRuleUpdateActionById 981175 pass")
		res = append(res, "SecRuleUpdateActionById 981176 pass")
		res = append(res, "SecRuleUpdateActionById 981200 pass")
		res = append(res, "SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'175',t:none,deny,log,msg:'Inbound Attack Targeting OSVDB Flagged Resource.',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule RESOURCE:OSVDB_VULNERABLE \"@eq 1\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\"")
		res = append(res, "SecRule TX:ANOMALY_SCORE \"@gt 0\" \"chain,phase:2,id:'981176',t:none,deny,log,msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.ANOMALY_SCORE}, SQLi=%{TX.SQL_INJECTION_SCORE}, XSS=%{TX.XSS_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}',setvar:tx.inbound_tx_msg=%{tx.msg},setvar:tx.inbound_anomaly_score=%{tx.anomaly_score}\" \n SecRule TX:ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_level}\" chain \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d+\\-/ \"(.*)\"")
		res = append(res, "SecRule TX:OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_level}\" \"chain,phase:4,id:'981200',t:none,deny,msg:'Outbound Anomaly Score Exceeded (score %{TX.OUTBOUND_ANOMALY_SCORE}): Last Matched Message: %{tx.msg}',logdata:'Last Matched Data: %{matched_var}'\" \n SecRule TX:ANOMALY_SCORE_BLOCKING \"@streq on\" chain \n SecRule TX:/^\\d/ \"(.*)\"")

		// TODO: Make sense to have rules in phase 1 and 3?
		// res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		// res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'outbound_blocking=%{tx.blocking_outbound_anomaly_score},sql_injection_score=%{tx.sql_injection_score},xss_score=%{tx.xss_score},tag:'reporting'\"")
		return res
	case "3":
		res = append(res, "SecRuleUpdateActionById 949100 pass")
		res = append(res, "SecRule IP:REPUT_BLOCK_FLAG \"@eq 1\" \"id:100,phase:2,deny,log,msg:'Request Denied by IP Reputation Enforcement',logdata:'Previous Block Reason: %{ip.reput_block_reason}',tag:'application-multi',tag:'language-multi',tag:'platform-multi',tag:'attack-reputation-ip',severity:'CRITICAL',chain \n SecRule TX:DO_REPUT_BLOCK \"@eq 1\" \"setvar:'tx.inbound_anomaly_score=%{tx.anomaly_score}'")
		res = append(res, "SecRuleUpdateActionById 949110 pass")
		res = append(res, "SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, deny, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")
		res = append(res, "SecRuleUpdateActionById 959100 pass")
		res = append(res, "SecRule TX:BLOCKING_OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_threshold}\" \"id:959102, phase:4, deny, t:none, msg:'%{TX.BLOCKING_OUTBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")

		// TODO: Review presence of Combined Score
		res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		return res
	case "4":
		res = append(res, "SecRuleUpdateActionById 949110 pass")
		res = append(res, "SecRule TX:BLOCKING_INBOUND_ANOMALY_SCORE \"@ge %{tx.inbound_anomaly_score_threshold}\" \"id:949112, phase:2, deny, t:none, msg:'%{TX.BLOCKING_INBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")
		res = append(res, "SecRuleUpdateActionById 959100 pass")
		res = append(res, "SecRule TX:BLOCKING_OUTBOUND_ANOMALY_SCORE \"@ge %{tx.outbound_anomaly_score_threshold}\" \"id:959102, phase:4, deny, t:none, msg:'%{TX.BLOCKING_OUTBOUND_ANOMALY_SCORE}', tag:'anomaly-evaluation'\"")
		
		if cf.Get().Options["early_blocking"] == "true" { 
			res = append(res, "SecAction phase:1,setvar:'tx.early_blocking=1'")
		}

		res = append(res, "SecAction \"id:171,phase:1,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:172,phase:2,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:173,phase:3,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		res = append(res, "SecAction \"id:174,phase:4,pass,t:none,noauditlog,msg:'inbound_blocking=%{tx.blocking_inbound_anomaly_score},inbound_detection=%{tx.detection_inbound_anomaly_score},inbound_per_pl=%{tx.inbound_anomaly_score_pl1}-%{tx.inbound_anomaly_score_pl2}-%{tx.inbound_anomaly_score_pl3}-%{tx.inbound_anomaly_score_pl4},inbound_threshold=%{tx.inbound_anomaly_score_threshold},outbound_blocking=%{tx.blocking_outbound_anomaly_score},outbound_detection=%{tx.detection_outbound_anomaly_score},outbound_per_pl=%{tx.outbound_anomaly_score_pl1}-%{tx.outbound_anomaly_score_pl2}-%{tx.outbound_anomaly_score_pl3}-%{tx.outbound_anomaly_score_pl4},outbound_threshold=%{tx.outbound_anomaly_score_threshold},SQLI=%{tx.sql_injection_score},XSS=%{tx.xss_score},RFI=%{tx.rfi_score},LFI=%{tx.lfi_score},RCE=%{tx.rce_score},PHPI=%{tx.php_injection_score},HTTP=%{tx.http_violation_score},SESS=%{tx.session_fixation_score},COMBINED_SCORE=%{tx.anomaly_score}',tag:'reporting'\"")
		return res
	default:
		return []string{
		}
	}
}