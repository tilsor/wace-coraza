package waceWAF

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"
	lg "github.com/tilsor/ModSecIntl_logging/logging"
	cf "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core/configstore"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

type WaceWAF struct {
	coraza.WAF
	exceptionWAF  coraza.WAF
	waceWafConfig *waceWAFConfig
	logger 	  	  *lg.Logging
}

type WaceTransaction struct {
	types.Transaction
	exceptionTransaction types.Transaction
	waf                  *WaceWAF
	requestLine          *string
	requestHeaders       *string
	requestBody          *string
	responseStatusCode   *int
	responseLine         *string
	responseHeaders      *string
	responseBody         *string
	CRSExecTime          *int64
	IntegrationTime 	 *int64
	startTime             time.Time
}

var gConfig *generalConfig
var ctx = context.Background()
var meter metric.Meter

func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {

	if gConfig == nil {
		gConfig = new(generalConfig)
		err := gConfig.LoadConfig("waceconfig.yaml")
		if err != nil {
			return nil, fmt.Errorf("Error loading general config: %v", err)
		}
		InitMetrics(ctx, gConfig.otelURL)
		wace.Init(getWaceMeter())
		errLog := lg.Get().LoadLogger(cf.Get().LogPath, cf.Get().LogLevel)
		if errLog != nil {
			return nil, fmt.Errorf("Error loading logger: %v", errLog)
		}
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

// Implements the NewTransaction interfaces provided by Coraza WAF to return a new WaceTransaction transaction
// TODO: Delete the debug prints
func (w *WaceWAF) NewTransaction() types.Transaction {
	start := time.Now()

	CRSTransaction := w.WAF.NewTransaction()
	w.logger.StartTransaction(CRSTransaction.ID())

	var integrationTime int64 = time.Since(start).Nanoseconds()
	var crsTime int64 = time.Since(start).Nanoseconds()
	t := WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransaction(), w, new(string), new(string), new(string), new(int), new(string), new(string), new(string), &crsTime, &integrationTime, start}
	w.logger.TPrintln(lg.DEBUG,CRSTransaction.ID(), "New WACEWAF transaction created")
	return t
}

func (t WaceTransaction) ProcessURI(uri string, method string, httpVersion string) {
	start := time.Now()
	t.Transaction.ProcessURI(uri, method, httpVersion)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.ProcessURI(uri, method, httpVersion)
	*t.requestLine = method + " " + uri + " " + httpVersion

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "URI processed: " + uri)
}

// TODO: Analyze if the interface SetServerName of the transaction should be implemented
func (t WaceTransaction) SetServerName(serverName string) {
	start := time.Now()
	t.Transaction.SetServerName(serverName)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.SetServerName(serverName)
	*t.requestHeaders += "Server: " + serverName + "\n"
	
	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Server name set: " + serverName)
}

// TODO: Check how the headers are appended to the variable
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddRequestHeader(key, value)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.AddRequestHeader(key, value)
	*t.requestHeaders += key + ": " + value + "\n"
	
	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Request header added: " + key + ": " + value)
}

// Implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
// TODO: Add early check for phase 1
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	start := time.Now()
	go func() {
		t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing request headers by WACE and Coraza")

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

				if cf.Get().LogLevel == lg.DEBUG { // Para no ejecutar el for, no se que util sera esto
					for _, model := range activeModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.reqHeadModelIDs
		}

		// wace.AnalyzeReqLineAndHeaders(t.Transaction.ID(), *t.requestLine, *t.requestHeaders, activeModels)

		err := wace.Analyze("RequestHeaders", t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders, activeModels)
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing request headers by WACE: " + err.Error())
		}
		// duration, _ := meter.Float64Histogram("http.client.request.headers.exceptions.duration.seconds")
		// duration.Record(ctx, (float64(time.Since(start).Nanoseconds())))
	}()

	interruption := t.Transaction.ProcessRequestHeaders()
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

		res, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

		if err == nil {
			if res {
				t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Transaction blocked")
				interruption = &types.Interruption{Action: "deny"}

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

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	startTime := time.Now()
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	*t.requestBody = string(b)
	readTime := time.Since(startTime).Nanoseconds()

	interruption, cantB, err := t.exceptionTransaction.ReadRequestBodyFrom(r)

	if err != nil {
		return interruption, 0, err
	}

	start := time.Now()
	interruption, cantB, err = t.Transaction.ReadRequestBodyFrom(r)
	*t.CRSExecTime += time.Since(start).Nanoseconds() + readTime

	duration, err := meter.Float64Histogram("http.client.request.body.read.duration.seconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	return interruption, cantB, err
}

// Implements the ProcessRequestBody interface provided by Coraza WAF to process request body by WACE and Coraza
func (t WaceTransaction) ProcessRequestBody() (*types.Interruption, error) {
	start := time.Now()
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

				if cf.Get().LogLevel == lg.DEBUG { // idem anterior
					for _, model := range activeRequestModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["RequestBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["RequestBody"] {
				requestBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeRequestBodyModels = ParseActiveModels(requestBodyExceptionRuleMessage)

				if cf.Get().LogLevel == lg.DEBUG { // idem anterior
					for _, model := range activeRequestBodyModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}
		} else {
			activeRequestBodyModels = t.waf.waceWafConfig.waceModels.reqBodyModelIDs
			activeRequestModels = t.waf.waceWafConfig.waceModels.reqModelIDs
		}
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing request body by WACE and Coraza")

			// wace.AnalyzeRequestBody(t.Transaction.ID(), *t.requestBody, activeRequestBodyModels)

			err := wace.Analyze("RequestBody", t.Transaction.ID(), *t.requestBody, activeRequestBodyModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing request body by WACE: " + err.Error())
			}
		}()
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing request by WACE and Coraza")

			//wace.AnalyzeRequest(t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders+"\n"+*t.requestBody, activeRequestModels)

			err := wace.Analyze("AllRequest", t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders+"\n"+*t.requestBody, activeRequestModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing request by WACE: " + err.Error())
			}
		}()
		duration, _ := meter.Float64Histogram("http.client.request.body.exceptions.duration.seconds")
		duration.Record(ctx, (float64(time.Since(start).Nanoseconds())))
	}()

	interruption, err := t.Transaction.ProcessRequestBody()
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	if err != nil {
		t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing request body by Coraza: " + err.Error())
	}

	mtRules := t.MatchedRules()

	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "2"

	// TODO: Get decision plugin id from the configstore
	result, err2 := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

	if err2 == nil {
		if result {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Transaction blocked")

			interruption = &types.Interruption{Action: "deny"}

			blocked, err2 := meter.Int64Counter("http.client.request.blockedp2.total")
			if err2 != nil {
				panic(err2)
			}
			blocked.Add(ctx, 1)
		}
	}


	*t.IntegrationTime += time.Since(start).Nanoseconds()

	// tiempo = time.Now()
	return interruption, err
}

func (t WaceTransaction) AddResponseHeader(key string, value string) {
	// //fmt.Printf("[DEBUG][WACE] Adding response header: %v: %d\n", key, time.Since(tiempo).Milliseconds())
	start := time.Now()
	t.Transaction.AddResponseHeader(key, value)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.AddResponseHeader(key, value)
	*t.responseHeaders += key + ": " + value + "\n"

	
	*t.IntegrationTime += time.Since(start).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Response header added: " + key + ": " + value)
}

// var tiempo time.Time

// Implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
// TODO: Check for a better function to parse status code
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	start := time.Now()

	*t.responseStatusCode = code
	*t.responseLine = proto + " " + fmt.Sprint(code)
	go func() {
		t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing response headers by WACE and Coraza")

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

				if cf.Get().LogLevel == lg.DEBUG { // idem anterior
					for _, model := range activeModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.respHeadModelIDs
		}
		// wace.AnalyzeRespLineAndHeaders(t.Transaction.ID(), *t.responseLine, *t.responseHeaders, activeModels)

		err := wace.Analyze("ResponseHeaders", t.Transaction.ID(), *t.responseLine+"\n"+*t.responseHeaders, activeModels)
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing response headers by WACE: " + err.Error())
		}

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

		res, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

		if err == nil {
			if res {
				t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Transaction blocked")

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

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	startTime := time.Now()
	*t.responseBody = string(b)
	toStringTime := time.Since(startTime).Nanoseconds()

	interruption, cantB, err := t.exceptionTransaction.WriteResponseBody(b)

	start := time.Now()
	if err != nil {
		return interruption, 0, err
	}

	interruption, cantB, err = t.Transaction.WriteResponseBody(b)
	*t.CRSExecTime += time.Since(start).Nanoseconds() + toStringTime

	duration, err := meter.Float64Histogram("http.client.response.body.read.duration.seconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	
	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Response body written")
	return interruption, cantB, err
}

// Implements the ProcessResponseBody interface provided by Coraza WAF to process response body by WACE and Coraza
func (t WaceTransaction) ProcessResponseBody() (*types.Interruption, error) {
	start := time.Now()
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

				if cf.Get().LogLevel == lg.DEBUG { // idem anterior
					for _, model := range activeResponseModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != gConfig.ruleIdsForExceptions["ResponseBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == gConfig.ruleIdsForExceptions["ResponseBody"] {
				responseBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeResponseBodyModels = ParseActiveModels(responseBodyExceptionRuleMessage)

				if cf.Get().LogLevel == lg.DEBUG { // idem anterior
					for _, model := range activeResponseBodyModels {
						t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Active model: " + model)
					}
				}
			}
		} else {
			activeResponseBodyModels = t.waf.waceWafConfig.waceModels.respBodyModelIDs
			activeResponseModels = t.waf.waceWafConfig.waceModels.respModelIDs
		}

		go func() {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing response body by WACE and Coraza")

			// wace.AnalyzeResponseBody(t.Transaction.ID(), *t.responseBody, activeResponseBodyModels)

			err := wace.Analyze("ResponseBody", t.Transaction.ID(), *t.responseBody, activeResponseBodyModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing response body by WACE: " + err.Error())
			}
		}()
		go func() {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Processing response by WACE and Coraza")

			// wace.AnalyzeResponse(t.Transaction.ID(), *t.responseLine+"\n"+*t.responseHeaders+"\n"+*t.responseBody, activeResponseModels)

			err := wace.Analyze("AllResponse", t.Transaction.ID(), *t.requestBody, activeResponseModels)
			if err != nil {
				t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error processing response by WACE: " + err.Error())
			}
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

	res, err2 := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionId, wafParams)

	if err2 == nil {
		if res {
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Transaction blocked")
			
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

func (t WaceTransaction) ProcessLogging() {
	start := time.Now()
	t.Transaction.ProcessLogging()
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	go wace.CloseTransaction(t.Transaction.ID())

	go func() {
		execTime, err := meter.Int64Histogram("http.client.request.processed.CRSExecTime.seconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error getting CRS histogram: " + err.Error())
		} else {
			execTime.Record(ctx, *t.CRSExecTime)
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "CRS Execution time: " + fmt.Sprint(*t.CRSExecTime/1000000) + " ms")
		}

		duration, err := meter.Float64Histogram("http.client.request.processed.duration.seconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error getting request histogram: " + err.Error())
		} else{
			duration.Record(ctx, (float64(time.Since(t.startTime).Nanoseconds())))
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Total Execution time: " + fmt.Sprint(time.Since(t.startTime).Milliseconds()) + " ms")
		}

		processed, err := meter.Int64Counter("http.client.request.processed.total")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error getting processed counter: " + err.Error())
		} else {
			processed.Add(ctx, 1, metric.WithAttributes(semconv.HTTPResponseStatusCode(*t.responseStatusCode)))
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Request processed")
		}

		*t.IntegrationTime += time.Since(start).Nanoseconds()
		durationInt, err := meter.Float64Histogram("http.client.integration.processed.duration.seconds")
		if err != nil {
			t.waf.logger.TPrintln(lg.ERROR,t.Transaction.ID(), "Error getting integration histogram: " + err.Error())
		} else {
			durationInt.Record(ctx, (float64(*t.IntegrationTime)))
			t.waf.logger.TPrintln(lg.DEBUG,t.Transaction.ID(), "Integration time: " + fmt.Sprint(*t.IntegrationTime/1000000) + " ms")
		}
	}()
}

var serviceName = semconv.ServiceNameKey.String("waceWAF-service")

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

// Initializes an OTLP exporter, and configures the corresponding meter provider.
func initMeterProvider(ctx context.Context, res *resource.Resource, conn *grpc.ClientConn) (func(context.Context) error, error) {
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(2*time.Second))),
		sdkmetric.WithResource(res),
	)

	// Check if MeterProvider is already setted
	if otel.GetMeterProvider() != nil {
		//fmt.Printf("MeterProvider already setted")
	} else {
		//fmt.Printf("MeterProvider not setted")
	}

	globalMeterProvider = meterProvider
	meter = globalMeterProvider.Meter("waceWAF")

	return meterProvider.Shutdown, nil
}

var globalMeterProvider *sdkmetric.MeterProvider

func getWaceMeter() metric.Meter {
	return globalMeterProvider.Meter("wace")
}

func InitMetrics(ctx context.Context, url string) {
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

	_, err = initMeterProvider(ctx, res, conn)
	if err != nil {
		panic(err)
	}
	// defer func() {
	// 	if err := shutdownMeterProvider(ctx); err != nil {
	// 		panic(err) // TODO handle error
	// 	}
	// }()
}
