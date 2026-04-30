package waceWAF

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	lg "github.com/tilsor/ModSecIntl_logging/logging"
	wace "github.com/tilsor/ModSecIntl_wace_lib"

	pm "github.com/tilsor/ModSecIntl_wace_lib/pluginmanager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// WaceWAF implements the WAF interface provided by Coraza WAF and adds the WACE functionality to it
type WaceWAF struct {
	coraza.WAF
	exceptionWAF  coraza.WAF
	waceWafConfig *waceWAFConfig
	logger        *lg.Logging
}

// WaceTransaction implements the Transaction interface provided by Coraza WAF and adds the WACE functionality to it
type WaceTransaction struct {
	types.Transaction
	exceptionTransaction types.Transaction
	waf                  *WaceWAF
	httpPayload          *pm.HTTPPayload
	CRSExecTime          *int64
	IntegrationTime      *int64
	startTime            time.Time
	coordinator          *sync.WaitGroup
}

var gConfig *generalConfig
var ctx = context.Background()
var meter metric.Meter
var configFilePath string

func init() {
	configFilePath = "waceconfig.yaml"
}

// NewWAF creates a new WaceWAF object with the given configuration
func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {

	if gConfig == nil {
		gConfig = new(generalConfig)
		confData, err := gConfig.LoadConfig(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("Error loading general config: %v", err)
		}

		InitMetrics(ctx, gConfig.otelURL)
		// Initialize WACE call, wich validate and test configs
		err = wace.Init(getWaceMeter(), confData.ConfigFileData)
		if err != nil {
			return nil, fmt.Errorf("Error WACE initialize failed: %v", err)
		}

		// After plugins are validated, we get the default plugin values.
		gConfig.setDefaultPlugins(confData)
	}

	wafConfigs, ok := config.(*waceWAFConfig)

	if !ok {
		return nil, fmt.Errorf("Error casting to waceWAFConfig")
	}

	if wafConfigs.waceAppConfigFilePath != "" {
		err := wafConfigs.LoadConfig(wafConfigs.waceAppConfigFilePath)
		if err != nil {
			return nil, fmt.Errorf("Error loading waceAppConfig: %v", err)
		}
	} else {
		wafConfigs.LoadConfigFromGeneralConfig(*gConfig)
	}

	// Get rules by CRS Version
	configRules := wafConfigs.getConfigRules(gConfig.crsVersion)

	for _, rule := range configRules {
		wafConfigs.WAFConfig = wafConfigs.WAFConfig.WithDirectives(rule)
	}

	waf, err := coraza.NewWAF(wafConfigs.WAFConfig)

	if err != nil {
		return nil, err
	}

	if wafConfigs.exceptionsFilePath != "" {
		wafConfigs.exceptionsConfig = wafConfigs.LoadExceptionsDirectives(wafConfigs.exceptionsFilePath, wafConfigs.waceModels)
	}

	exceptionsWaf, err := coraza.NewWAF(wafConfigs.exceptionsConfig)

	if err != nil {
		return nil, err
	}

	return &WaceWAF{waf, exceptionsWaf, wafConfigs, lg.Get()}, err
}

// NewTransaction implements the NewTransaction interface provided by Coraza WAF to create a new WaceTransaction
// which implements the Transaction interface provided by Coraza WAF and adds the WACE functionality to it
func (w *WaceWAF) NewTransaction() types.Transaction {
	start := time.Now()

	CRSTransaction := w.WAF.NewTransaction()

	var integrationTime int64 = time.Since(start).Nanoseconds()
	var crsTime int64 = time.Since(start).Nanoseconds()
	wace.InitTransaction(CRSTransaction.ID())
	t := WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransaction(), w, new(pm.HTTPPayload), &crsTime, &integrationTime, start, new(sync.WaitGroup)}
	w.logger.TPrintln(lg.DEBUG, CRSTransaction.ID(), "New WACEWAF transaction created")
	return t
}

// NewTransactionWithID implements the NewTransactionWithID interface provided by Coraza WAF to create a new WaceTransaction
// which implements the Transaction interface provided by Coraza WAF and adds the WACE functionality to it
func (w *WaceWAF) NewTransactionWithID(id string) types.Transaction {
	start := time.Now()

	CRSTransaction := w.WAF.NewTransactionWithID(id)

	var integrationTime int64 = time.Since(start).Nanoseconds()
	var crsTime int64 = time.Since(start).Nanoseconds()
	wace.InitTransaction(CRSTransaction.ID())
	t := WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransactionWithID(id), w, new(pm.HTTPPayload), &crsTime, &integrationTime, start, new(sync.WaitGroup)}
	w.logger.TPrintln(lg.DEBUG, CRSTransaction.ID(), "New WACEWAF transaction created")
	return t
}

// ProcessUri implements the ProcessURI interface provided by Coraza WAF to process the URI by WACE and Coraza
func (t WaceTransaction) ProcessURI(uri string, method string, httpVersion string) {
	start := time.Now()
	t.Transaction.ProcessURI(uri, method, httpVersion)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.ProcessURI(uri, method, httpVersion)
	t.httpPayload.URI = uri
	t.httpPayload.Method = method
	t.httpPayload.HTTPVersion = httpVersion
	// *t.requestLine = method + " " + uri + " " + httpVersion

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "URI processed: "+uri)
}

// // SetServerName implements the SetServerName interface provided by Coraza WAF to set the server name by WACE and Coraza
// func (t WaceTransaction) SetServerName(serverName string) {
// 	start := time.Now()
// 	t.Transaction.SetServerName(serverName)
// 	*t.CRSExecTime += time.Since(start).Nanoseconds()

// 	t.exceptionTransaction.SetServerName(serverName)
// 	*t.requestHeaders += "Server: " + serverName + "\n"

// 	*t.IntegrationTime += time.Since(start).Nanoseconds()

// 	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Server name set: "+serverName)
// }

// AddRequestHeader implements the AddRequestHeader interface provided by Coraza WAF to add a request header by WACE and Coraza
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddRequestHeader(key, value)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.AddRequestHeader(key, value)
	t.httpPayload.RequestHeaders = append(t.httpPayload.RequestHeaders, pm.HTTPHeader{Key: key, Value: value})
	// *t.requestHeaders += key + ": " + value + "\n"

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Request header added: "+key+": "+value)
}

// ProcessRequestHeaders implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	start := time.Now()
	t.coordinator.Add(1)
	go func() {
		t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing request headers by WACE and Coraza")

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessRequestHeaders()

			activeModels = []string{}
			requestHeadersExceptionRuleMessage := ""
			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["RequestHeaders"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["RequestHeaders"] {
				requestHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeModels = ParseActiveModels(requestHeadersExceptionRuleMessage)

				// TODO: review logger
				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.reqHeadModelIDs
		}

		exceptionsDuration, err := meter.Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting exceptions histogram: "+err.Error())
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "1")))
		}

		err = wace.Analyze("RequestHeaders", t.Transaction.ID(), *t.httpPayload, activeModels)
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing request headers by WACE: "+err.Error())
		}
		t.coordinator.Done()
	}()

	interruption := t.Transaction.ProcessRequestHeaders()
	if interruption != nil {
		t.httpPayload.ResponseCode = interruption.Status
	}
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	if t.waf.waceWafConfig.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "1"

		t.coordinator.Wait()
		res, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

		if err == nil {
			if res {
				t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Transaction blocked")
				interruption = &types.Interruption{Action: "deny"}
				t.httpPayload.ResponseCode = 403

				blocked, err := meter.Int64Counter("http.client.request.blockedp1.total")
				if err != nil {
					panic(err)
				}
				blocked.Add(ctx, 1)
			}
		}
	}

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	return interruption
}

// ReadRequestBodyFrom implements the ReadRequestBodyFrom interface provided by Coraza WAF to read the request body by WACE and Coraza
func (t WaceTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	startTime := time.Now()
	var buf bytes.Buffer
	tee := io.TeeReader(r, &buf)
	b, err1 := io.ReadAll(tee)
	if err1 != nil {
		return nil, 0, err1
	}
	t.httpPayload.RequestBody = string(b)

	interruption, _, err2 := t.exceptionTransaction.ReadRequestBodyFrom(&buf)

	if err2 != nil {
		return interruption, 0, err2
	}

	start := time.Now()
	interruption2, cantB2, err := t.Transaction.ReadRequestBodyFrom(&buf)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	duration, err := meter.Float64Histogram("http.client.request.body.read.duration.nanoseconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Request body read "+t.httpPayload.RequestBody)
	return interruption2, cantB2, err
}

// ProcessRequestBody implements the ProcessRequestBody interface provided by Coraza WAF to process the request body by WACE and Coraza
func (t WaceTransaction) ProcessRequestBody() (*types.Interruption, error) {
	start := time.Now()
	t.coordinator.Add(2)
	go func() {
		var activeRequestBodyModels []string
		var activeRequestModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessRequestBody()

			requestBodyExceptionRuleMessage := ""
			requestExceptionRuleMessage := ""

			activeRequestBodyModels = []string{}
			activeRequestModels = []string{}

			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["AllRequest"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["AllRequest"] {
				requestExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeRequestModels = ParseActiveModels(requestExceptionRuleMessage)

				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeRequestModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["RequestBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["RequestBody"] {
				requestBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeRequestBodyModels = ParseActiveModels(requestBodyExceptionRuleMessage)

				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeRequestBodyModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}
		} else {
			activeRequestBodyModels = t.waf.waceWafConfig.waceModels.reqBodyModelIDs
			activeRequestModels = t.waf.waceWafConfig.waceModels.reqModelIDs
		}
		exceptionsDuration, err := meter.Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting exceptions histogram: "+err.Error())
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "2")))
		}
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing request body by WACE and Coraza")

			err := wace.Analyze("RequestBody", t.Transaction.ID(), pm.HTTPPayload{RequestBody: t.httpPayload.RequestBody}, activeRequestBodyModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing request body by WACE: "+err.Error())
			}
			t.coordinator.Done()
		}()
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing request by WACE and Coraza")

			err := wace.Analyze("AllRequest", t.Transaction.ID(), *t.httpPayload, activeRequestModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing request by WACE: "+err.Error())
			}
			t.coordinator.Done()
		}()
	}()

	interruption, err := t.Transaction.ProcessRequestBody()
	if err != nil {
		t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing request body by Coraza: "+err.Error())
	}
	if interruption != nil {
		t.httpPayload.ResponseCode = interruption.Status
	}
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	if err != nil {
		t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing request body by Coraza: "+err.Error())
	}

	mtRules := t.MatchedRules()

	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "2"

	t.coordinator.Wait()
	result, err2 := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

	if err2 == nil {
		if result {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Transaction blocked")

			interruption = &types.Interruption{Action: "deny"}
			t.httpPayload.ResponseCode = 403

			blocked, err2 := meter.Int64Counter("http.client.request.blockedp2.total")
			if err2 != nil {
				panic(err2)
			}
			blocked.Add(ctx, 1)
		}
	}

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	return interruption, err
}

func (t WaceTransaction) AddResponseHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddResponseHeader(key, value)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.AddResponseHeader(key, value)
	t.httpPayload.ResponseHeaders = append(t.httpPayload.ResponseHeaders, pm.HTTPHeader{Key: key, Value: value})
	// *t.responseHeaders += key + ": " + value + "\n"

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Response header added: "+key+": "+value)
}

// ProcessResponseHeaders implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	start := time.Now()

	t.httpPayload.ResponseCode = code
	t.httpPayload.ResponseProtocol = proto
	// *t.responseLine = proto + " " + fmt.Sprint(code)
	t.coordinator.Add(1)
	go func() {
		t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing response headers by WACE and Coraza")

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessResponseHeaders(code, proto)

			responseHeadersExceptionRuleMessage := ""
			activeModels = []string{}

			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["ResponseHeaders"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["ResponseHeaders"] {
				responseHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeModels = ParseActiveModels(responseHeadersExceptionRuleMessage)

				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.respHeadModelIDs
		}

		exceptionsDuration, err := meter.Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting exceptions histogram: "+err.Error())
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "3")))
		}

		err = wace.Analyze("ResponseHeaders", t.Transaction.ID(), pm.HTTPPayload{ResponseCode: t.httpPayload.ResponseCode, ResponseProtocol: t.httpPayload.ResponseProtocol, ResponseHeaders: t.httpPayload.ResponseHeaders}, activeModels)
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing response headers by WACE: "+err.Error())
		}

		t.coordinator.Done()
	}()

	interruption := t.Transaction.ProcessResponseHeaders(code, proto)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	if t.waf.waceWafConfig.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "3"

		t.coordinator.Wait()
		res, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

		if err == nil {
			if res {
				t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Transaction blocked")

				interruption = &types.Interruption{Action: "deny"}

				blocked, err := meter.Int64Counter("http.client.request.blockedp3.total")
				if err != nil {
					panic(err)
				}
				blocked.Add(ctx, 1)
			}
		}
	}

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	return interruption
}

// WriteResponseBody implements the WriteResponseBody interface provided by Coraza WAF to write the response body by WACE and Coraza
func (t WaceTransaction) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	startTime := time.Now()
	t.httpPayload.ResponseBody = string(b)

	interruption, cantB, err := t.exceptionTransaction.WriteResponseBody(b)

	start := time.Now()
	if err != nil {
		return interruption, 0, err
	}

	interruption, cantB, err = t.Transaction.WriteResponseBody(b)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	duration, err := meter.Float64Histogram("http.client.response.body.read.duration.nanoseconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Response body written")
	return interruption, cantB, err
}

// ProcessResponseBody implements the ProcessResponseBody interface provided by Coraza WAF to process the response body by WACE and Coraza
func (t WaceTransaction) ProcessResponseBody() (*types.Interruption, error) {
	start := time.Now()
	t.coordinator.Add(2)
	go func() {

		var activeResponseBodyModels []string
		var activeResponseModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessResponseBody()
			responseBodyExceptionRuleMessage := ""
			responseExceptionRuleMessage := ""
			activeResponseBodyModels = []string{}
			activeResponseModels = []string{}

			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["AllResponse"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["AllResponse"] {
				responseExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeResponseModels = ParseActiveModels(responseExceptionRuleMessage)

				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeResponseModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["ResponseBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["ResponseBody"] {
				responseBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeResponseBodyModels = ParseActiveModels(responseBodyExceptionRuleMessage)

				// if cf.Get().LogLevel == lg.DEBUG {
				for _, model := range activeResponseBodyModels {
					t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Active model: "+model)
				}
				// }
			}
		} else {
			activeResponseBodyModels = t.waf.waceWafConfig.waceModels.respBodyModelIDs
			activeResponseModels = t.waf.waceWafConfig.waceModels.respModelIDs
		}

		exceptionsDuration, err := meter.Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting exceptions histogram: "+err.Error())
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "4")))
		}

		go func() {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing response body by WACE and Coraza")

			err := wace.Analyze("ResponseBody", t.Transaction.ID(), pm.HTTPPayload{ResponseBody: t.httpPayload.ResponseBody}, activeResponseBodyModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing response body by WACE: "+err.Error())
			}
			t.coordinator.Done()
		}()
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Processing response by WACE and Coraza")

			err := wace.Analyze("AllResponse", t.Transaction.ID(), pm.HTTPPayload{ResponseCode: t.httpPayload.ResponseCode, ResponseProtocol: t.httpPayload.ResponseProtocol, ResponseHeaders: t.httpPayload.ResponseHeaders, ResponseBody: t.httpPayload.ResponseBody}, activeResponseModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error processing response by WACE: "+err.Error())
			}
			t.coordinator.Done()
		}()
	}()

	interruption, err := t.Transaction.ProcessResponseBody()
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	mtRules := t.MatchedRules()
	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "4"

	t.coordinator.Wait()
	res, err2 := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

	if err2 == nil {
		if res {
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Transaction blocked")

			interruption = &types.Interruption{Action: "deny"}

			blocked, err2 := meter.Int64Counter("http.client.request.blockedp4.total")
			if err2 != nil {
				panic(err2)
			}
			blocked.Add(ctx, 1)
		}
	}

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	return interruption, err
}

// ProcessLogging implements the ProcessLogging interface provided by Coraza WAF to process logging by WACE and Coraza
func (t WaceTransaction) ProcessLogging() {
	start := time.Now()
	t.Transaction.ProcessLogging()
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	go wace.CloseTransaction(t.Transaction.ID())

	go func() {
		execTime, err := meter.Int64Histogram("http.client.request.processed.CRSExecTime.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting CRS histogram: "+err.Error())
		} else {
			execTime.Record(ctx, *t.CRSExecTime)
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "CRS Execution time: "+fmt.Sprint(*t.CRSExecTime/1000000)+" ms")
		}

		duration, err := meter.Float64Histogram("http.client.request.processed.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting request histogram: "+err.Error())
		} else {
			duration.Record(ctx, (float64(time.Since(t.startTime).Nanoseconds())))
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Total Execution time: "+fmt.Sprint(time.Since(t.startTime).Milliseconds())+" ms")
		}

		processed, err := meter.Int64Counter("http.client.request.processed.total")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting processed counter: "+err.Error())
		} else {
			processed.Add(ctx, 1, metric.WithAttributes(semconv.HTTPResponseStatusCode(t.httpPayload.ResponseCode)))
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Request processed")
		}

		*t.IntegrationTime += time.Since(start).Nanoseconds()
		durationInt, err := meter.Float64Histogram("http.client.integration.processed.duration.nanoseconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR, t.Transaction.ID(), "Error getting integration histogram: "+err.Error())
		} else {
			durationInt.Record(ctx, (float64(*t.IntegrationTime)))
			t.waf.logger.TPrintln(lg.DEBUG, t.Transaction.ID(), "Integration time: "+fmt.Sprint(*t.IntegrationTime/1000000)+" ms")
		}
	}()
}

var serviceName = semconv.ServiceNameKey.String("waceWAF-service")

// initConn creates a gRPC connection to the OpenTelemetry Collector. It returns the connection object and an error if the connection fails.
// This function is based on the example provided by OpenTelemetry Go contrib repository.
// https://github.com/open-telemetry/opentelemetry-go-contrib/blob/main/examples/otel-collector/main.go
func initConn(url string) (*grpc.ClientConn, error) {
	// It connects the OpenTelemetry Collector through local gRPC connection.
	// You may replace `localhost:4317` with your endpoint.
	if url == "" {
		url = "localhost:4317"
	}
	conn, err := grpc.NewClient(url,
		// Note the use of insecure transport here. TLS is recommended in production.
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to collector: %w", err)
	}

	return conn, err
}

// initMeterProvider initializes an OTLP exporter, and configures the corresponding meter provider.
func initMeterProvider(ctx context.Context, res *resource.Resource, conn *grpc.ClientConn) (func(context.Context) error, error) {
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(2*time.Second))),
		sdkmetric.WithResource(res),
	)

	globalMeterProvider = meterProvider
	meter = globalMeterProvider.Meter("waceWAF")

	return meterProvider.Shutdown, nil
}

var globalMeterProvider metric.MeterProvider

// getWaceMeter returns the meter for the WACE instrumentation.
func getWaceMeter() metric.Meter {
	return globalMeterProvider.Meter("wace")
}

// InitMetrics initializes the OpenTelemetry metrics instrumentation.
func InitMetrics(ctx context.Context, url string) (func(context.Context) error, error) {
	if url == "" {
		globalMeterProvider = noop.NewMeterProvider()
		otel.SetMeterProvider(globalMeterProvider)
		meter = globalMeterProvider.Meter("waceWAF")
		return func(_ context.Context) error { return nil }, nil
	}

	conn, err := initConn(url)
	if err != nil {
		panic(err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			serviceName,
		),
	)
	if err != nil {
		panic(err)
	}

	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(2*time.Second))),
		sdkmetric.WithResource(res),
	)

	globalMeterProvider = meterProvider
	meter = globalMeterProvider.Meter("waceWAF")

	return meterProvider.Shutdown, nil
}
