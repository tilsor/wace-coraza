# WACE WAF

---

## Introduction



## Configuration
This section provides details on each field within the configuration files and their purposes. These configurations are necessary to control how the system processes requests, handles plugins, manages logging, and more.

### File: waceconfig.yaml
Logging is not configured in this file. Call `waceWAF.SetLogger` with a `*slog.Logger` before `NewWAF` (by default `slog.Default()` is used). The logger must not carry a `component` attribute: WACE WAF logs with `component=waf` and the WACE core adds its own.

**Plugins configuration**
- model_plugins: Defines the plugins used for processing transactions.
  - id (String): a unique identifier for each model plugin.
  - plugintype (String): Specifies the plugin type. Possible values include "RequestHeaders", "RequestBody", "AllRequest", "ResponseHeaders", "ResponseBody", and "AllResponse".
  - path (String): file path to the plugin executable file.
  - weight (Float): defines the weight of this plugin in scoring decisions.
  - mode (String): execution mode, values can be "sync" or "async".
  - remote (Boolean): indicates whether the plugin is executed through NATS.

- decision_plugins: contains plugins used to determine final actions based on model plugin outputs.
  - id (String): identifier for each decision plugin.
  - path (String): file path to the plugin executable file.
  - params: Contains parameters for decision-making logic.
    - waf_weight (String): weight assigned to Web Application Firewall (WAF) in decision scoring.
    - threshold (String): minimum threshold score to apply the decision plugin’s result.

**Network and Options**

- natsurl (String): URL for the NATS server, which handles messaging between components. Default format is hostname:port.
- otel_url (String): URL for the OpenTelemetry collector in order to send metrics.
- crs_version (String): version of the OWASP CRS in use.
- early_blocking (Boolean): enables or disables early blocking of requests.
- blocking (Boolean): enables or disables denying transactions based on the WACE decision plugin's result. When false, transactions are still analyzed and scored, but never denied. If a per-app waceappconfig.yaml is used, its own `blocking` value takes priority over this one.

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
- modelids (List): a list of model plugin IDs to be applied in this application. Each ID SHOULD match a modelplugin defined in the main configuration.
- decisionid (String): specifies the ID of the decision plugin to use. This ID should correspond to one in the decisionplugins section of the main configuration.
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

## Contributing

Merge requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
