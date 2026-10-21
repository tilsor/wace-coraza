# WACE WAF

---

## Introduction



## Configuration
This section provides details on each field within the configuration files and their purposes. These configurations are necessary to control how the system processes requests, handles plugins, manages logging, and more.

### File: waceconfig.yaml
The file is read from the path in the `WACE_CONFIG_FILEPATH` environment variable, or from `waceconfig.yaml` in the working directory.

The file is read once, by the first `NewWAF` or `waceWAF.Reload`, whichever comes first. `NewWAF` never reads it again: to apply changes without restarting, call `waceWAF.Reload` with a `*slog.Logger` (or nil for `slog.Default()`). `Reload` compares the parsed configuration, so changes in comments or formatting are ignored; if nothing else changed, it only replaces the logger. If the new configuration is rejected, the previous one is kept.

`crs_version` and `exception_ids` cannot change on reload: a `Reload` that changes them is rejected, and every later one too, until they are reverted or the process is restarted. In Caddy, the rejection fails the config load, so Caddy keeps running the previous config.

A WAF keeps the configuration it was created with, so the WAFs have to be created again after a `Reload` that changes it. `waceWAF.ConfigVersion` returns an identifier of the part of the configuration WAFs are built with: when it changes, the WAFs have to be recreated; when only plugin parameters or other fields applied by the WACE core change, it does not.

A `Reload` is not undone if the integration later discards the reload for another reason: for example, if another module fails the Caddy config load after `Reload` applied the configuration, the WAFs of the previous Caddy config keep running with the new WACE core configuration until the next successful load.

Logging is not configured in this file. `NewWAF` uses the logger set by `waceWAF.SetLogger`, which replaces it without reading the file, and `Reload` sets the one it gets. The logger must not carry a `component` attribute: WACE WAF logs with `component=wace-waf` and the WACE core adds its own.

**Plugins configuration**
- model_plugins: Defines the plugins used for processing transactions.
  - id (String): a unique identifier for each model plugin.
  - plugin_type (String): Specifies the plugin type. Possible values are "RequestHeaders", "RequestBody", "AllRequest", "ResponseHeaders", "ResponseBody", "AllResponse", and "Everything".
  - path (String): file path to the plugin executable file.
  - async (Boolean): execution mode. When true, the plugin is evaluated asynchronously and its result is not awaited within the request; when false (the default), it is evaluated synchronously during the transaction.
  - remote (Boolean): indicates whether the plugin is executed through NATS.
  - sanitize (Boolean): when true, the headers listed in `credential_headers` are stripped from the data sent to this plugin.
  - timeout (Duration, optional): per-plugin override of the model timeout. `0` means no timeout. When unset, `model_timeout` (sync plugins) or `async_model_timeout` (async plugins) applies.
  - training (Boolean): when true, the plugin is used only for data collection and is not applied to applications by default.
  - training_data: data-collection parameters, used when `training` is true (`min_samples`, `max_samples`, `result_file_path`, `status_file_path`, `status_update_interval`).
  - params: plugin-specific parameters passed to the plugin.

- decision_plugins: contains plugins used to determine final actions based on model plugin outputs.
  - id (String): identifier for each decision plugin.
  - path (String): file path to the plugin executable file.
  - model_weights (Map): weight assigned to each model plugin's score in decision scoring, keyed by model id.
  - waf_weight (Float): weight assigned to the WAF (CRS) anomaly score in decision scoring.
  - timeout (Duration, optional): bounds each call to the plugin. `0` means no timeout. See `fail_closed` for what happens when it is exceeded.
  - training (Boolean), training_data: as in model plugins.
  - params: Contains parameters for decision-making logic.
    - threshold (String): minimum threshold score to apply the decision plugin’s result.

**Network and Options**

- nats_url (String): URL for the NATS server, which handles messaging between components. Default format is hostname:port.
- credential_headers (List of String, optional): the header names stripped from the data sent to model plugins that have `sanitize` enabled. Default `["authorization", "cookie", "set-cookie"]`.
- model_timeout (Duration, optional): default time bound for synchronous model plugins. When omitted, the default (200ms) is used; `0` disables the timeout. A model plugin's own `timeout` overrides it.
- async_model_timeout (Duration, optional): default time bound for asynchronous model plugins. When omitted, the default (60s) is used; `0` disables the timeout. A model plugin's own `timeout` overrides it.
- otel_url (String, optional): address of the OTLP gRPC receiver of an OpenTelemetry Collector, as `host:port` (e.g. `localhost:4317`). When set, the metrics of WACE WAF and of the WACE core are exported there every 2 seconds, without TLS. When empty or missing, no metrics are recorded. It can be changed by a reload: the new address is used once the new configuration is accepted, and the metrics still pending for the old one are flushed.
- crs_version (String): version of the OWASP CRS in use. When it is empty, WACE injects no CRS integration directives at all (the same effect as `disable_crs` applied to every application), so the CRS ruleset does not need to be loaded.
- early_blocking (Boolean): enables or disables early blocking of requests.
- blocking (Boolean): enables or disables denying transactions based on the WACE decision plugin's result. When false, transactions are still analyzed and scored, but never denied. This is independent of Coraza's `SecRuleEngine` directive: `SecRuleEngine` governs whether the CRS/SecLang rules deny a transaction, while `blocking` governs whether the WACE decision denies it. If a per-app waceappconfig.yaml is used, its own `blocking` value takes priority over this one.
- fail_closed (Boolean, optional, default false): when true, transactions are denied if the WACE decision plugin cannot decide (e.g. it fails or exceeds the decision plugin's `timeout`). When false, they are let through. It only has effect when `blocking` is enabled. It governs the decision plugin's timeout and failures only; it does not apply to `model_timeout` or `async_model_timeout` (a model plugin that times out does not, by itself, block the transaction).

**Rule IDs for Exceptions**

- exception_ids (optional): the IDs of the rules that WACE adds after the exceptions file to report which models are still active. Their values only need to be unique and must not collide with the rules of the exceptions file. Every key is optional: a missing one takes its default value. Unknown keys, non-positive IDs and repeated IDs are rejected when the configuration is loaded.
  - RequestHeaders: ID for exceptions related to request headers (default 9000100).
  - RequestBody: ID for exceptions related to request bodies (default 9000200).
  - AllRequest: ID for exceptions applied to all requests (default 9000300).
  - ResponseHeaders: ID for exceptions related to response headers (default 9000400).
  - ResponseBody: ID for exceptions related to response bodies (default 9000500).
  - AllResponse: ID for exceptions applied to all responses (default 9000600).
  - Everything: ID for exceptions applied to the whole transaction (default 9000700).

  WACE also adds a rule with ID 9000000 before the exceptions file, which marks every model as active; it cannot be configured.

### File: <app>waceappconfig.yaml
- model_ids (List): a list of model plugin IDs to be applied in this application. Each ID SHOULD match a model plugin defined in the main configuration.
- decision_ids (List): the IDs of the decision plugins to use. Each ID should correspond to one in the `decision_plugins` section of the main configuration. Exactly one must be a non-training decision plugin.
- early_blocking (Boolean): overrides the general config's early_blocking for this application.
- disable_crs (Boolean): when true, skips injecting the OWASP CRS-specific directives (CRS blocking-rule neutralization and anomaly-score reporting rules) for this application, so the CRS ruleset does not need to be loaded at all. Custom SecLang rules (e.g. virtual patches) are unaffected and still apply.
- blocking (Boolean): overrides the general config's blocking for this application.
- app_name (String): the name of the application. This can be used for identification purposes.

### File: waceexceptions.conf

This file defines models exception using SecLang syntax. In order to except a particular model, you need to add in your rule the following directive:
  ```bash
  setvar:tx.<model_id>=false
  ```
By default, all models defined in the configuration are applied to each transaction.

## Metrics

When `otel_url` is set, WACE WAF exports the following metrics (alongside the WACE core's own) to the OpenTelemetry Collector every 2 seconds. The duration histograms share the same bucket boundaries, from 100µs to 10s.

| Metric | Instrument | Unit | Attributes | Description |
| --- | --- | --- | --- | --- |
| `wace.waf.exceptions.duration` | Histogram | s | `phase` | Time from the start of a phase until its exceptions are evaluated and the active models known. |
| `wace.waf.request.body.read.duration` | Histogram | s | — | Time spent reading the request body. |
| `wace.waf.response.body.write.duration` | Histogram | s | — | Time spent writing a chunk of the response body. |
| `wace.waf.crs.duration` | Histogram | s | — | Time spent by Coraza processing a transaction. |
| `wace.waf.integration.duration` | Histogram | s | — | Time spent by WACE WAF processing a transaction, Coraza included. |
| `wace.waf.transaction.duration` | Histogram | s | — | Time from the creation of a transaction until it is logged. |
| `wace.waf.transaction.processed` | Counter | `{transaction}` | `http.response.status_code` | Transactions logged, by response status code. |
| `wace.waf.transaction.blocked` | Counter | `{transaction}` | `phase` | Transactions blocked by the WACE decision, by phase. |

## Contributing

Merge requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
