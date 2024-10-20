package waceWAF

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	wace "gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core"

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
}

type WaceTransaction struct {
	types.Transaction
	exceptionTransaction types.Transaction
	waf                  *WaceWAF
	requestLine          *string
	requestHeaders       *string
	requestBody          *string
	responseLine         *string
	responseHeaders      *string
	responseBody         *string
}

var ctx = context.Background()
var CRSExecTime sync.Map
var meter metric.Meter
var startTime sync.Map

func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {

	wafConfigs, ok := config.(*waceWAFConfig)

	if !ok {
		return nil, fmt.Errorf("Error casting to waceWAFConfig")
	}

	wafConfigs.LoadConfig(wafConfigs.waceConfigFilePath)

	wace.Init()

	// Get rules by CRS Version
	configRules := wafConfigs.getConfigRules(wafConfigs.crsVersion)

	for _, rule := range configRules {
		wafConfigs.WAFConfig = wafConfigs.WAFConfig.WithDirectives(rule)
	}

	waf, err := coraza.NewWAF(wafConfigs.WAFConfig)

	waceModels := NewWaceModelsConfig()
	wafConfigs.waceModels = waceModels

	if wafConfigs.exceptionsFilePath != "" {
		wafConfigs.exceptionsConfig = wafConfigs.LoadExceptionsDirectives(wafConfigs.exceptionsFilePath, waceModels)
	}

	exceptionsWaf, err := coraza.NewWAF(wafConfigs.exceptionsConfig)

	InitMetrics(ctx)

	return &WaceWAF{waf, exceptionsWaf, wafConfigs}, err
}

func addCRSExecTime(transactionID string, addExecTime int64) {
	currentExecTime, ok := CRSExecTime.Load(transactionID)
	if ok {
		CRSExecTime.Store(transactionID, currentExecTime.(int64)+addExecTime)
	} else {
		CRSExecTime.Store(transactionID, addExecTime)
	}
}

// Implements the NewTransaction interfaces provided by Coraza WAF to return a new WaceTransaction transaction
// TODO: Delete the debug prints
func (w *WaceWAF) NewTransaction() types.Transaction {
	fmt.Println("[DEBUG][WACE] New wace-Coraza transaction")

	start := time.Now()
	CRSTransaction := w.WAF.NewTransaction()
	addCRSExecTime(CRSTransaction.ID(), time.Since(start).Nanoseconds())

	// Add start time to the context
	meter = otel.Meter("metrics")
	transactionCounter, err := meter.Int64Counter("http.client.request.started.count")
	if err != nil {
		panic(err)
	}
	transactionCounter.Add(ctx, 1)
	println("Total transactions: ", transactionCounter)
	startTime.Store(CRSTransaction.ID(), start)

	return WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransaction(), w, new(string), new(string), new(string), new(string), new(string), new(string)}
}

func (t WaceTransaction) ProcessURI(uri string, method string, httpVersion string) {
	start := time.Now()
	t.Transaction.ProcessURI(uri, method, httpVersion)
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	t.exceptionTransaction.ProcessURI(uri, method, httpVersion)
	*t.requestLine = method + " " + uri + " " + httpVersion
}

// TODO: Analyze if the interface SetServerName of the transaction should be implemented
func (t WaceTransaction) SetServerName(serverName string) {
	start := time.Now()
	t.Transaction.SetServerName(serverName)
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	t.exceptionTransaction.SetServerName(serverName)
	*t.requestHeaders += "Server: " + serverName + "\n"
}

// TODO: Check how the headers are appended to the variable
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddRequestHeader(key, value)
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	t.exceptionTransaction.AddRequestHeader(key, value)
	*t.requestHeaders += key + ": " + value + "\n"
}

// Implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
// TODO: Add early check for phase 1
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	start := time.Now()
	go func() {
		fmt.Println("[DEBUG][WACE] Processing request headers by WACE and Coraza")

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessRequestHeaders()

			activeModels = []string{}
			requestHeadersExceptionRuleMessage := ""
			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["RequestHeaders"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["RequestHeaders"] {
				requestHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeModels = ParseActiveModels(requestHeadersExceptionRuleMessage)

				for _, model := range activeModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.reqHeadModelIDs
		}

		// wace.AnalyzeReqLineAndHeaders(t.Transaction.ID(), *t.requestLine, *t.requestHeaders, activeModels)

		err := wace.Analyze("RequestHeaders", t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders, activeModels)
		if err != nil {
			fmt.Printf("[ERROR][WACE] Error processing request headers by WACE: %v\n", err)
		}
	}()

	interruption := t.Transaction.ProcessRequestHeaders()
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	if t.waf.waceWafConfig.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "1"

		res, err := wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

		if err == nil {
			if res {
				fmt.Println("[DEBUG][WACE] Transaction blocked")
				interruption = &types.Interruption{Action: "deny"}

				meter = otel.Meter("metrics")
				blocked, err := meter.Int64Counter("http.client.request.blockedp1.count")
				if err != nil {
					panic(err)
				}
				blocked.Add(ctx, 1)
				println("Phase 1 blocked transactions: ", blocked)
			}
		}
	}

	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) ReadRequestBodyFrom(r io.Reader) (*types.Interruption, int, error) {
	start := time.Now()
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	*t.requestBody = string(b)
	readTime := time.Since(start).Nanoseconds()

	interruption, cantB, err := t.exceptionTransaction.ReadRequestBodyFrom(r)

	if err != nil {
		return interruption, 0, err
	}

	start = time.Now()
	interruption, cantB, err = t.Transaction.ReadRequestBodyFrom(r)
	addCRSExecTime(t.Transaction.ID(), (time.Since(start).Nanoseconds() + readTime))

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
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["AllRequest"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["AllRequest"] {
				requestExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeRequestModels = ParseActiveModels(requestExceptionRuleMessage)
				for _, model := range activeRequestModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["RequestBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["RequestBody"] {
				requestBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeRequestBodyModels = ParseActiveModels(requestBodyExceptionRuleMessage)
				for _, model := range activeRequestBodyModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}
		} else {
			activeRequestBodyModels = t.waf.waceWafConfig.waceModels.reqBodyModelIDs
			activeRequestModels = t.waf.waceWafConfig.waceModels.reqModelIDs
		}
		go func() {
			fmt.Println("[DEBUG][WACE] Processing request body by WACE and Coraza")

			// wace.AnalyzeRequestBody(t.Transaction.ID(), *t.requestBody, activeRequestBodyModels)

			err := wace.Analyze("RequestBody", t.Transaction.ID(), *t.requestBody, activeRequestBodyModels)
			if err != nil {
				fmt.Printf("[ERROR][WACE] Error processing request body by WACE: %v\n", err)
			}
		}()
		go func() {
			fmt.Println("[DEBUG][WACE] Processing request by WACE and Coraza")

			//wace.AnalyzeRequest(t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders+"\n"+*t.requestBody, activeRequestModels)

			err := wace.Analyze("AllRequest", t.Transaction.ID(), *t.requestLine+"\n"+*t.requestHeaders+"\n"+*t.requestBody, activeRequestBodyModels)
			if err != nil {
				fmt.Printf("[ERROR][WACE] Error processing request by WACE: %v\n", err)
			}
		}()
	}()

	interruption, err := t.Transaction.ProcessRequestBody()
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	if err != nil {
		fmt.Println("[DEBUG][WACE] Error processing request body by Coraza: " + err.Error())
	}

	mtRules := t.MatchedRules()

	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "2"

	fmt.Printf("%v", wafParams)
	// TODO: Get decision plugin id from the configstore
	result, err := wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

	if err == nil {
		if result {
			fmt.Println("[DEBUG][WACE] Transaction blocked")
			interruption = &types.Interruption{Action: "deny"}

			meter = otel.Meter("metrics")
			blocked, err := meter.Int64Counter("http.client.request.blockedp2.count")
			if err != nil {
				panic(err)
			}
			blocked.Add(ctx, 1)
			println("Phase 2 blocked transactions: ", blocked)
		}
	}

	return interruption, err
}

func (t WaceTransaction) AddResponseHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddResponseHeader(key, value)
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	t.exceptionTransaction.AddResponseHeader(key, value)
	*t.responseHeaders += key + ": " + value + "\n"
}

// Implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
// TODO: Check for a better function to parse status code
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	start := time.Now()

	*t.responseLine = proto + " " + fmt.Sprint(code)
	go func() {
		fmt.Println("[DEBUG][WACE] Processing response headers by WACE and Coraza")

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessResponseHeaders(code, proto)

			responseHeadersExceptionRuleMessage := ""
			activeModels = []string{}

			i := len(t.exceptionTransaction.MatchedRules()) - 1
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["ResponseHeaders"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["ResponseHeaders"] {
				responseHeadersExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeModels = ParseActiveModels(responseHeadersExceptionRuleMessage)

				for _, model := range activeModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}
		} else {
			activeModels = t.waf.waceWafConfig.waceModels.respHeadModelIDs
		}
		// wace.AnalyzeRespLineAndHeaders(t.Transaction.ID(), *t.responseLine, *t.responseHeaders, activeModels)

		err := wace.Analyze("ResponseHeaders", t.Transaction.ID(), *t.responseLine+"\n"+*t.responseHeaders, activeModels)
		if err != nil {
			fmt.Printf("[ERROR][WACE] Error processing response headers by WACE: %v\n", err)
		}

	}()

	interruption := t.Transaction.ProcessResponseHeaders(code, proto)
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	if t.waf.waceWafConfig.earlyBlocking {
		mtRules := t.MatchedRules()
		mtRulesLen := len(mtRules)

		wafParams := map[string]string{}
		for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
			scoreParts := strings.Split(score, "=")
			wafParams[scoreParts[0]] = scoreParts[1]
		}
		wafParams["phase"] = "3"

		res, err := wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

		if err == nil {
			if res {
				fmt.Println("[DEBUG][WACE] Transaction blocked")
				interruption = &types.Interruption{Action: "deny"}

				meter = otel.Meter("metrics")
				blocked, err := meter.Int64Counter("http.client.request.blockedp3.count")
				if err != nil {
					panic(err)
				}
				blocked.Add(ctx, 1)
				println("Phase 3 blocked transactions: ", blocked)
			}
		}
	}

	return interruption
}

// TODO: Analyze if these actions can be done in parallel
func (t WaceTransaction) WriteResponseBody(b []byte) (*types.Interruption, int, error) {
	start := time.Now()
	*t.responseBody = string(b)
	toStringTime := time.Since(start).Nanoseconds()

	interruption, cantB, err := t.exceptionTransaction.WriteResponseBody(b)

	start = time.Now()
	if err != nil {
		return interruption, 0, err
	}

	interruption, cantB, err = t.Transaction.WriteResponseBody(b)
	addCRSExecTime(t.Transaction.ID(), (time.Since(start).Nanoseconds() + toStringTime))

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
			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["AllResponse"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["AllResponse"] {
				responseExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeResponseModels = ParseActiveModels(responseExceptionRuleMessage)
				for _, model := range activeResponseModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}

			for i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() != t.waf.waceWafConfig.ruleIdsForExceptions["ResponseBody"] {
				i--
			}
			if i > 0 && t.exceptionTransaction.MatchedRules()[i].Rule().ID() == t.waf.waceWafConfig.ruleIdsForExceptions["ResponseBody"] {
				responseBodyExceptionRuleMessage = t.exceptionTransaction.MatchedRules()[i].Message()
				activeResponseBodyModels = ParseActiveModels(responseBodyExceptionRuleMessage)
				for _, model := range activeResponseBodyModels {
					fmt.Println("[DEBUG][WACE] Active model: ", model)
				}
			}
		} else {
			activeResponseBodyModels = t.waf.waceWafConfig.waceModels.respBodyModelIDs
			activeResponseModels = t.waf.waceWafConfig.waceModels.respModelIDs
		}

		go func() {
			fmt.Println("[DEBUG][WACE] Processing response body by WACE and Coraza")

			// wace.AnalyzeResponseBody(t.Transaction.ID(), *t.responseBody, activeResponseBodyModels)

			err := wace.Analyze("ResponseBody", t.Transaction.ID(), *t.responseBody, activeResponseBodyModels)
			if err != nil {
				fmt.Printf("[ERROR][WACE] Error processing response body by WACE: %v\n", err)
			}
		}()
		go func() {
			fmt.Println("[DEBUG][WACE] Processing response by WACE and Coraza")

			// wace.AnalyzeResponse(t.Transaction.ID(), *t.responseLine+"\n"+*t.responseHeaders+"\n"+*t.responseBody, activeResponseModels)

			err := wace.Analyze("AllResponse", t.Transaction.ID(), *t.requestBody, activeResponseModels)
			if err != nil {
				fmt.Printf("[ERROR][WACE] Error processing response by WACE: %v\n", err)
			}
		}()
	}()

	interruption, err := t.Transaction.ProcessResponseBody()
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())

	mtRules := t.MatchedRules()
	mtRulesLen := len(mtRules)

	wafParams := map[string]string{}
	for _, score := range strings.Split(mtRules[mtRulesLen-1].Message(), ",") {
		scoreParts := strings.Split(score, "=")
		wafParams[scoreParts[0]] = scoreParts[1]
	}
	wafParams["phase"] = "4"

	res, err := wace.CheckTransaction(t.Transaction.ID(), "simple", wafParams)

	if err == nil {
		if res {
			fmt.Println("[DEBUG][WACE] Transaction blocked")
			interruption = &types.Interruption{Action: "deny"}

			meter = otel.Meter("metrics")
			blocked, err := meter.Int64Counter("http.client.request.blockedp4.count")
			if err != nil {
				panic(err)
			}
			blocked.Add(ctx, 1)
			println("Phase 4 blocked transactions: ", blocked)
		}
	}

	return interruption, err
}

func (t WaceTransaction) ProcessLogging() {
	start := time.Now()
	t.Transaction.ProcessLogging()
	addCRSExecTime(t.Transaction.ID(), time.Since(start).Nanoseconds())
	CRSExecutionTime, ok := CRSExecTime.Load(t.Transaction.ID())
	CRSExecTime.Delete(t.Transaction.ID())
	if ok {
		meter := otel.Meter("metrics")
		execTime, err := meter.Int64Histogram("http.client.request.processed.execTime")
		if err != nil {
			panic(err)
		}
		execTime.Record(ctx, CRSExecutionTime.(int64))
		println("CRS execution time: ", execTime)
	}

	meter := otel.Meter("metrics")
	duration, err := meter.Float64Histogram("http.client.request.processed.duration")
	if err != nil {
		panic(err)
	}
	startT, ok := startTime.Load(t.Transaction.ID())
	startTime.Delete(t.Transaction.ID())
	if ok {
		duration.Record(ctx, (float64(time.Since(startT.(time.Time).Round(time.Millisecond)).Milliseconds())))
		println("Duration: ", duration)
	}

	processed, err := meter.Int64Counter("http.client.request.processed.count")
	if err != nil {
		panic(err)
	}
	processed.Add(ctx, 1)
	println("Processed transactions: ", processed)
}

var serviceName = semconv.ServiceNameKey.String("waceWAF-service")

// https://github.com/open-telemetry/opentelemetry-go-contrib/blob/main/examples/otel-collector/main.go
func initConn() (*grpc.ClientConn, error) {
	// It connects the OpenTelemetry Collector through local gRPC connection.
	// You may replace `localhost:4317` with your endpoint.
	conn, err := grpc.NewClient("localhost:4317",
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
	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown, nil
}

func InitMetrics(ctx context.Context) {
	conn, err := initConn()
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
