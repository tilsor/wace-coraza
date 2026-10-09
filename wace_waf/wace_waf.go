package waceWAF

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"

	wace "github.com/tilsor/ModSecIntl_wace_lib"

	cs "github.com/tilsor/ModSecIntl_wace_lib/configstore"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

const (
	DEFAULT_CONFIG_FILEPATH = "waceconfig.yaml"
	WACE_CONFIG_FILEPATH    = "WACE_CONFIG_FILEPATH"
)

// WaceWAF implements the WAF interface provided by Coraza WAF and adds the WACE functionality to it
type WaceWAF struct {
	coraza.WAF
	exceptionWAF  coraza.WAF
	waceWafConfig *WaceWAFConfig
}

// WaceTransaction implements the Transaction interface provided by Coraza WAF and adds the WACE functionality to it
type WaceTransaction struct {
	types.Transaction
	exceptionTransaction types.Transaction
	waf                  *WaceWAF
	httpPayload          *waceapi.HTTPPayload
	CRSExecTime          *int64
	IntegrationTime      *int64
	startTime            time.Time
	coordinator          *sync.WaitGroup
}

var gConfig *generalConfig
var ctx = context.Background()

var configFilePath string

// componentName is the value of the component attribute of the WACE WAF
// logs. The WACE core adds its own.
const componentName = "wace-waf"

// loggers holds the logger given to SetLogger, passed as is to the WACE
// core, and the one WACE WAF logs with, which adds the component
// attribute. They are stored together so they are always replaced at once.
type loggers struct {
	core *slog.Logger
	waf  *slog.Logger
}

// currentLoggers holds the current loggers. It is replaced by SetLogger.
var currentLoggers atomic.Pointer[loggers]

// SetLogger replaces the logger of WACE WAF. If l is nil, slog.Default()
// is used. l must not carry a component attribute: WACE WAF and the WACE
// core add their own.
func SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	currentLoggers.Store(&loggers{
		core: l,
		waf:  l.With(waceapi.LogKeyComponent, componentName),
	})
}

// getLogger returns the logger of WACE WAF, with the component attribute.
func getLogger() *slog.Logger {
	return currentLoggers.Load().waf
}

// getCoreLogger returns the logger passed to the WACE core, without the
// component attribute.
func getCoreLogger() *slog.Logger {
	return currentLoggers.Load().core
}

func resolveConfigFilePath() string {
	if envFilePath := os.Getenv(WACE_CONFIG_FILEPATH); envFilePath != "" {
		return envFilePath
	}
	return DEFAULT_CONFIG_FILEPATH
}

func init() {
	configFilePath = resolveConfigFilePath()
	SetLogger(nil)
}

// NewWAF creates a new WaceWAF object with the given configuration
func NewWAF(config coraza.WAFConfig) (*WaceWAF, error) {
	if gConfig == nil {
		gConfig = new(generalConfig)
		data, err := os.ReadFile(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("Error loading general config: %v", err)
		}

		confData, err := gConfig.LoadConfig(data)
		if err != nil {
			return nil, fmt.Errorf("Error loading general config: %v", err)
		}

		metrics, err := newMetrics(ctx, gConfig.otelURL)
		if err != nil {
			return nil, fmt.Errorf("Error initializing metrics: %v", err)
		}
		// Initialize WACE call, wich validate and test configs
		err = wace.Init(metrics.provider, confData.ConfigFileData, getCoreLogger())
		if err != nil {
			shutdownMetrics(metrics)
			return nil, fmt.Errorf("Error WACE initialize failed: %v", err)
		}
		shutdownMetrics(currentMetrics.Swap(metrics))

		// After plugins are validated, we get the default plugin values.
		gConfig.setDefaultPlugins(confData)

		gConfig.hash = dataHash(data)

	} else {
		newGC := new(generalConfig)
		data, err := os.ReadFile(configFilePath)
		if err != nil {
			return nil, fmt.Errorf("Error loading general config: %v", err)
		}
		h := dataHash(data)
		// Check for changes on default config
		if h != gConfig.hash {
			confData, err := newGC.LoadConfig(data)
			if err != nil {
				return nil, fmt.Errorf("Error loading general config: %v", err)
			}

			// The metrics are only replaced once the WACE core accepts
			// the new configuration.
			metrics := currentMetrics.Load()
			if gConfig.otelURL != newGC.otelURL {
				metrics, err = newMetrics(ctx, newGC.otelURL)
				if err != nil {
					return nil, fmt.Errorf("Error initializing metrics: %v", err)
				}
			}

			err = wace.Reload(metrics.provider, confData.ConfigFileData, getCoreLogger())
			if err != nil {
				if metrics != currentMetrics.Load() {
					shutdownMetrics(metrics)
				}
				return nil, fmt.Errorf("Error WACE reload failed: %v", err)
			}
			if old := currentMetrics.Swap(metrics); old != metrics {
				shutdownMetrics(old)
			}

			// After plugins are validated, we get the default plugin values.
			newGC.setDefaultPlugins(confData)

			gConfig = newGC
		}
	}

	wafConfigs, ok := config.(*WaceWAFConfig)

	if !ok {
		return nil, fmt.Errorf("Error casting to *WaceWAFConfig: use NewWaceWAFConfig or NewWAFConfig")
	}

	// Get rules by CRS Version
	configRules := []string{}

	if wafConfigs.waceAppConfigFilePath != "" || wafConfigs.waceConfigRaw != nil {

		// WACE App Config file takes precedence over the raw configuration data
		if wafConfigs.waceAppConfigFilePath != "" {
			conf, err := loadConfig(wafConfigs.waceAppConfigFilePath)
			if err != nil {
				return nil, fmt.Errorf("Error reading waceAppConfig file %s: %v", wafConfigs.waceAppConfigFilePath, err)
			}
			wafConfigs.waceConfigRaw = &conf
		}

		err := wafConfigs.loadWaceAppConfig(*wafConfigs.waceConfigRaw)
		if err != nil {
			return nil, fmt.Errorf("Error applying waceAppConfig: %v", err)
		}
		if !wafConfigs.disableCRS {
			configRules = wafConfigs.getConfigRules(gConfig.crsVersion)
		}
	} else {
		wafConfigs.LoadConfigFromGeneralConfig(*gConfig)
		configRules = wafConfigs.getConfigRules(gConfig.crsVersion)
	}

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
		return nil, fmt.Errorf("Error loading exceptions file %s: %v", wafConfigs.exceptionsFilePath, err)
	}

	return &WaceWAF{waf, exceptionsWaf, wafConfigs}, err
}

// NewTransaction implements the NewTransaction interface provided by Coraza WAF to create a new WaceTransaction
// which implements the Transaction interface provided by Coraza WAF and adds the WACE functionality to it
func (w *WaceWAF) NewTransaction() types.Transaction {
	start := time.Now()

	CRSTransaction := w.WAF.NewTransaction()

	var integrationTime int64 = time.Since(start).Nanoseconds()
	var crsTime int64 = time.Since(start).Nanoseconds()
	wace.InitTransaction(CRSTransaction.ID())
	t := WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransaction(), w, new(waceapi.HTTPPayload), &crsTime, &integrationTime, start, new(sync.WaitGroup)}
	getLogger().Debug("new WACEWAF transaction created", waceapi.LogKeyTxID, CRSTransaction.ID())
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
	t := WaceTransaction{CRSTransaction, w.exceptionWAF.NewTransactionWithID(id), w, new(waceapi.HTTPPayload), &crsTime, &integrationTime, start, new(sync.WaitGroup)}
	getLogger().Debug("new WACEWAF transaction created", waceapi.LogKeyTxID, CRSTransaction.ID())
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

	getLogger().Debug("URI processed", waceapi.LogKeyTxID, t.Transaction.ID())
}

// // SetServerName implements the SetServerName interface provided by Coraza WAF to set the server name by WACE and Coraza
// func (t WaceTransaction) SetServerName(serverName string) {
// 	start := time.Now()
// 	t.Transaction.SetServerName(serverName)
// 	*t.CRSExecTime += time.Since(start).Nanoseconds()

// 	t.exceptionTransaction.SetServerName(serverName)
// 	*t.requestHeaders += "Server: " + serverName + "\n"

// 	*t.IntegrationTime += time.Since(start).Nanoseconds()

// 	getLogger().Debug("server name set", waceapi.LogKeyTxID, t.Transaction.ID(), "server", serverName)
// }

// AddRequestHeader implements the AddRequestHeader interface provided by Coraza WAF to add a request header by WACE and Coraza
func (t WaceTransaction) AddRequestHeader(key string, value string) {
	start := time.Now()
	t.Transaction.AddRequestHeader(key, value)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.exceptionTransaction.AddRequestHeader(key, value)
	t.httpPayload.RequestHeaders = append(t.httpPayload.RequestHeaders, waceapi.HTTPHeader{Key: key, Value: value})
	// *t.requestHeaders += key + ": " + value + "\n"

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	getLogger().Debug("request header added", waceapi.LogKeyTxID, t.Transaction.ID(), "header", key)
}

// ProcessRequestHeaders implements the ProcessRequestHeaders interface provided by Coraza WAF to process request headers by WACE and Coraza
func (t WaceTransaction) ProcessRequestHeaders() *types.Interruption {
	start := time.Now()
	// The models get a copy: ResponseCode is written below while they run.
	payload := *t.httpPayload
	t.coordinator.Add(1)
	go func() {
		getLogger().Debug("processing request headers by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessRequestHeaders()
			activeModels, _ = t.exceptionActiveModels(cs.RequestHeaders)
		} else {
			activeModels = t.waf.waceWafConfig.waceModels[cs.RequestHeaders]
		}

		exceptionsDuration, err := getMeter().Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting exceptions histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "1")))
		}

		err = wace.Analyze(cs.RequestHeaders, t.Transaction.ID(), payload, activeModels)
		if err != nil {
			getLogger().Error("error processing request headers by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}
		t.coordinator.Done()
	}()

	interruption := t.Transaction.ProcessRequestHeaders()
	if interruption != nil {
		t.httpPayload.ResponseCode = interruption.Status
	}
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.coordinator.Wait()

	// Skip the WACE check if a disruptive rule already interrupted the
	// transaction: the reporting SecAction never ran and Coraza is already
	// blocking the request.
	if t.waf.waceWafConfig.earlyBlocking && interruption == nil {
		if wafScores, ok := parseScoreParams(t.MatchedRules(), "1"); ok {
			wafParams := waceapi.WAFData{
				Scores: wafScores,
				Rules:  processMatchedRules(t.MatchedRules()),
			}
			res, found, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionIds, wafParams)

			if !found {
				getLogger().Error("non-training decision plugin not found", waceapi.LogKeyTxID, t.Transaction.ID(), "decision.ids", t.waf.waceWafConfig.waceDecisionIds)
			} else if err == nil {
				if res && t.waf.waceWafConfig.blocking {
					getLogger().Debug("transaction blocked", waceapi.LogKeyTxID, t.Transaction.ID())
					interruption = &types.Interruption{Action: "deny"}
					t.httpPayload.ResponseCode = 403

					blocked, err := getMeter().Int64Counter("http.client.request.blockedp1.total")
					if err != nil {
						panic(err)
					}
					blocked.Add(ctx, 1)
				}
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

	duration, err := getMeter().Float64Histogram("http.client.request.body.read.duration.nanoseconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	getLogger().Debug("request body read", waceapi.LogKeyTxID, t.Transaction.ID(), "body.size", len(t.httpPayload.RequestBody))
	return interruption2, cantB2, err
}

// ProcessRequestBody implements the ProcessRequestBody interface provided by Coraza WAF to process the request body by WACE and Coraza
func (t WaceTransaction) ProcessRequestBody() (*types.Interruption, error) {
	start := time.Now()
	// The models get a copy: ResponseCode is written below while they run.
	payload := *t.httpPayload
	t.coordinator.Add(1)
	go func() {
		var activeRequestBodyModels []string
		var activeRequestModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessRequestBody()
			activeRequestBodyModels, _ = t.exceptionActiveModels(cs.RequestBody)
			activeRequestModels, _ = t.exceptionActiveModels(cs.AllRequest)
		} else {
			activeRequestBodyModels = t.waf.waceWafConfig.waceModels[cs.RequestBody]
			activeRequestModels = t.waf.waceWafConfig.waceModels[cs.AllRequest]
		}
		exceptionsDuration, err := getMeter().Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting exceptions histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "2")))
		}

		getLogger().Debug("processing request body by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		err = wace.Analyze(cs.RequestBody, t.Transaction.ID(), waceapi.HTTPPayload{RequestBody: payload.RequestBody}, activeRequestBodyModels)
		if err != nil {
			getLogger().Error("error processing request body by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}

		getLogger().Debug("processing request by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		err = wace.Analyze(cs.AllRequest, t.Transaction.ID(), payload, activeRequestModels)
		if err != nil {
			getLogger().Error("error processing request by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}
		t.coordinator.Done()
	}()

	interruption, err := t.Transaction.ProcessRequestBody()
	if err != nil {
		getLogger().Error("error processing request body by Coraza", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
	}
	if interruption != nil {
		t.httpPayload.ResponseCode = interruption.Status
	}
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	if err != nil {
		getLogger().Error("error processing request body by Coraza", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
	}

	t.coordinator.Wait()

	// Skip the WACE check if a disruptive rule already interrupted the
	// transaction: the reporting SecAction never ran and Coraza is already
	// blocking the request.
	if interruption == nil {
		if wafScores, ok := parseScoreParams(t.MatchedRules(), "2"); ok {
			wafParams := waceapi.WAFData{
				Scores: wafScores,
				Rules:  processMatchedRules(t.MatchedRules()),
			}
			res, found, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionIds, wafParams)

			if !found {
				getLogger().Error("non-training decision plugin not found", waceapi.LogKeyTxID, t.Transaction.ID(), "decision.ids", t.waf.waceWafConfig.waceDecisionIds)
			} else if err == nil {
				if res && t.waf.waceWafConfig.blocking {
					getLogger().Debug("transaction blocked", waceapi.LogKeyTxID, t.Transaction.ID())

					interruption = &types.Interruption{Action: "deny"}
					t.httpPayload.ResponseCode = 403

					blocked, err := getMeter().Int64Counter("http.client.request.blockedp2.total")
					if err != nil {
						panic(err)
					}
					blocked.Add(ctx, 1)
				}
			}
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
	t.httpPayload.ResponseHeaders = append(t.httpPayload.ResponseHeaders, waceapi.HTTPHeader{Key: key, Value: value})

	*t.IntegrationTime += time.Since(start).Nanoseconds()

	getLogger().Debug("response header added", waceapi.LogKeyTxID, t.Transaction.ID(), "header", key)
}

// ProcessResponseHeaders implements the ProcessResponseHeaders interface provided by Coraza WAF to process response headers by WACE and Coraza
func (t WaceTransaction) ProcessResponseHeaders(code int, proto string) *types.Interruption {
	start := time.Now()

	t.httpPayload.ResponseCode = code
	t.httpPayload.ResponseProtocol = proto
	t.coordinator.Add(1)
	go func() {
		getLogger().Debug("processing response headers by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		var activeModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessResponseHeaders(code, proto)
			activeModels, _ = t.exceptionActiveModels(cs.ResponseHeaders)
		} else {
			activeModels = t.waf.waceWafConfig.waceModels[cs.ResponseHeaders]
		}

		exceptionsDuration, err := getMeter().Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting exceptions histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "3")))
		}

		err = wace.Analyze(cs.ResponseHeaders, t.Transaction.ID(), waceapi.HTTPPayload{ResponseCode: t.httpPayload.ResponseCode, ResponseProtocol: t.httpPayload.ResponseProtocol, ResponseHeaders: t.httpPayload.ResponseHeaders}, activeModels)
		if err != nil {
			getLogger().Error("error processing response headers by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}

		t.coordinator.Done()
	}()

	interruption := t.Transaction.ProcessResponseHeaders(code, proto)
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.coordinator.Wait()

	// Skip the WACE check if a disruptive rule already interrupted the
	// transaction: the reporting SecAction never ran and Coraza is already
	// blocking the request.
	if t.waf.waceWafConfig.earlyBlocking && interruption == nil {
		if wafScores, ok := parseScoreParams(t.MatchedRules(), "3"); ok {
			wafParams := waceapi.WAFData{
				Scores: wafScores,
				Rules:  processMatchedRules(t.MatchedRules()),
			}
			res, found, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionIds, wafParams)

			if !found {
				getLogger().Error("non-training decision plugin not found", waceapi.LogKeyTxID, t.Transaction.ID(), "decision.ids", t.waf.waceWafConfig.waceDecisionIds)
			} else if err == nil {
				if res && t.waf.waceWafConfig.blocking {
					getLogger().Debug("transaction blocked", waceapi.LogKeyTxID, t.Transaction.ID())

					interruption = &types.Interruption{Action: "deny"}

					blocked, err := getMeter().Int64Counter("http.client.request.blockedp3.total")
					if err != nil {
						panic(err)
					}
					blocked.Add(ctx, 1)
				}
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

	duration, err := getMeter().Float64Histogram("http.client.response.body.read.duration.nanoseconds")
	duration.Record(ctx, (float64(time.Since(startTime).Nanoseconds())))

	*t.IntegrationTime += time.Since(startTime).Nanoseconds()

	getLogger().Debug("response body written", waceapi.LogKeyTxID, t.Transaction.ID())
	return interruption, cantB, err
}

// ProcessResponseBody implements the ProcessResponseBody interface provided by Coraza WAF to process the response body by WACE and Coraza
func (t WaceTransaction) ProcessResponseBody() (*types.Interruption, error) {
	start := time.Now()
	t.coordinator.Add(1)
	go func() {

		var activeResponseBodyModels []string
		var activeResponseModels []string
		var activeEverythingModels []string

		if t.waf.waceWafConfig.exceptionsFilePath != "" {
			t.exceptionTransaction.ProcessResponseBody()
			activeResponseBodyModels, _ = t.exceptionActiveModels(cs.ResponseBody)
			activeResponseModels, _ = t.exceptionActiveModels(cs.AllResponse)
			activeEverythingModels, _ = t.exceptionActiveModels(cs.Everything)
		} else {
			activeResponseBodyModels = t.waf.waceWafConfig.waceModels[cs.ResponseBody]
			activeResponseModels = t.waf.waceWafConfig.waceModels[cs.AllResponse]
			activeEverythingModels = t.waf.waceWafConfig.waceModels[cs.Everything]
		}

		exceptionsDuration, err := getMeter().Float64Histogram("http.exceptions.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting exceptions histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			exceptionsDuration.Record(ctx, (float64(time.Since(start).Nanoseconds())), metric.WithAttributes(attribute.String("phase", "4")))
		}

		getLogger().Debug("processing response body by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		err = wace.Analyze(cs.ResponseBody, t.Transaction.ID(), waceapi.HTTPPayload{ResponseBody: t.httpPayload.ResponseBody}, activeResponseBodyModels)
		if err != nil {
			getLogger().Error("error processing response body by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}
		getLogger().Debug("processing response by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		err = wace.Analyze(cs.AllResponse, t.Transaction.ID(), waceapi.HTTPPayload{ResponseCode: t.httpPayload.ResponseCode, ResponseProtocol: t.httpPayload.ResponseProtocol, ResponseHeaders: t.httpPayload.ResponseHeaders, ResponseBody: t.httpPayload.ResponseBody}, activeResponseModels)
		if err != nil {
			getLogger().Error("error processing response by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}

		getLogger().Debug("processing request and response by WACE and Coraza", waceapi.LogKeyTxID, t.Transaction.ID())

		payload := *t.httpPayload
		err = wace.Analyze(cs.Everything, t.Transaction.ID(), payload, activeEverythingModels)
		if err != nil {
			getLogger().Error("error processing request and response by WACE", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		}

		t.coordinator.Done()
	}()

	interruption, err := t.Transaction.ProcessResponseBody()
	*t.CRSExecTime += time.Since(start).Nanoseconds()

	t.coordinator.Wait()

	// Skip the WACE check if a disruptive rule already interrupted the
	// transaction: the reporting SecAction never ran and Coraza is already
	// blocking the request.
	if interruption == nil {
		if wafScores, ok := parseScoreParams(t.MatchedRules(), "4"); ok {
			wafParams := waceapi.WAFData{
				Scores: wafScores,
				Rules:  processMatchedRules(t.MatchedRules()),
			}
			res, found, err := wace.CheckTransaction(t.Transaction.ID(), t.waf.waceWafConfig.waceDecisionIds, wafParams)

			if !found {
				getLogger().Error("non-training decision plugin not found", waceapi.LogKeyTxID, t.Transaction.ID(), "decision.ids", t.waf.waceWafConfig.waceDecisionIds)
			} else if err == nil {
				if res && t.waf.waceWafConfig.blocking {
					getLogger().Debug("transaction blocked", waceapi.LogKeyTxID, t.Transaction.ID())

					interruption = &types.Interruption{Action: "deny"}

					blocked, err := getMeter().Int64Counter("http.client.request.blockedp4.total")
					if err != nil {
						panic(err)
					}
					blocked.Add(ctx, 1)
				}
			}
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

	wace.CloseTransaction(t.Transaction.ID())

	go func() {
		execTime, err := getMeter().Int64Histogram("http.client.request.processed.CRSExecTime.nanoseconds")
		if err != nil {
			getLogger().Error("error getting CRS histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			execTime.Record(ctx, *t.CRSExecTime)
			getLogger().Debug("CRS execution time", waceapi.LogKeyTxID, t.Transaction.ID(), "duration", time.Duration(*t.CRSExecTime))
		}

		duration, err := getMeter().Float64Histogram("http.client.request.processed.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting request histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			duration.Record(ctx, (float64(time.Since(t.startTime).Nanoseconds())))
			getLogger().Debug("total execution time", waceapi.LogKeyTxID, t.Transaction.ID(), "duration", time.Since(t.startTime))
		}

		processed, err := getMeter().Int64Counter("http.client.request.processed.total")
		if err != nil {
			getLogger().Error("error getting processed counter", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			processed.Add(ctx, 1, metric.WithAttributes(semconv.HTTPResponseStatusCode(t.httpPayload.ResponseCode)))
			getLogger().Debug("request processed", waceapi.LogKeyTxID, t.Transaction.ID())
		}

		*t.IntegrationTime += time.Since(start).Nanoseconds()
		durationInt, err := getMeter().Float64Histogram("http.client.integration.processed.duration.nanoseconds")
		if err != nil {
			getLogger().Error("error getting integration histogram", waceapi.LogKeyTxID, t.Transaction.ID(), "error", err)
		} else {
			durationInt.Record(ctx, (float64(*t.IntegrationTime)))
			getLogger().Debug("integration time", waceapi.LogKeyTxID, t.Transaction.ID(), "duration", time.Duration(*t.IntegrationTime))
		}
	}()
}

// exceptionActiveModels returns the models of type mt reported as active by
// the exceptions transaction, and whether the rule reporting them was matched.
// The exceptions WAF only adds that rule for types with models, so the matched
// rules are not searched when mt has none.
func (t WaceTransaction) exceptionActiveModels(mt cs.ModelPluginType) ([]string, bool) {
	if len(t.waf.waceWafConfig.waceModels[mt]) == 0 {
		return nil, false
	}
	ruleID := gConfig.ruleIdsForExceptions[mt.String()]
	rules := t.exceptionTransaction.MatchedRules()
	for i := len(rules) - 1; i >= 0; i-- {
		if rules[i].Rule().ID() != ruleID {
			continue
		}
		activeModels := parseActiveModels(rules[i].Message())
		for _, model := range activeModels {
			getLogger().Debug("active model", waceapi.LogKeyTxID, t.Transaction.ID(), "model", model)
		}
		return activeModels, true
	}
	return nil, false
}
