# WACE WAF

---

## Introduction



## Configuration
This section provides details on each field within the configuration files and their purposes. These configurations are necessary to control how the system processes requests, handles plugins, manages logging, and more.

### File: waceconfig.yaml
- logpath (String): Specifies the path to the log file where all WACE related logs will be stored. Default is typically set to /var/log/wace.log.
- loglevel (String): Sets the log level for the application. Possible values include DEBUG, INFO, WARN or ERROR.

**Plugins configuration**
- modelplugins: Defines the plugins used for processing transactions.
  - id (String): a unique identifier for each model plugin.
  - plugintype (String): Specifies the plugin type. Possible values include "RequestHeaders", "RequestBody", "AllRequest", "ResponseHeaders", "ResponseBody", and "AllResponse".
  - path (String): file path to the plugin executable file.
  - weight (Float): defines the weight of this plugin in scoring decisions.
  - mode (String): execution mode, values can be "sync" or "async".
  - remote (Boolean): indicates whether the plugin is executed through NATS.

- decisionplugins: contains plugins used to determine final actions based on model plugin outputs.
  - id (String): identifier for each decision plugin.
  - path (String): file path to the plugin executable file.
  - params: Contains parameters for decision-making logic.
    - waf_weight (String): weight assigned to Web Application Firewall (WAF) in decision scoring.
    - threshold (String): minimum threshold score to apply the decision plugin’s result.

**Network and Options**

- natsurl (String): URL for the NATS server, which handles messaging between components. Default format is hostname:port.
- options:
  - otelurl (String): URL for the OpenTelemetry collector in order to send metrics.
  - crs_version (String): version of the OWASP CRS in use.
  - early_blocking (String): enables or disables early blocking of requests (true or false).

**Rule IDs for Exceptions**

- ruleidsforexceptions: define the IDs used to configure default rules for model exceptions.
  - RequestHeaders: ID for exceptions related to request headers.
  - RequestBody: ID for exceptions related to request bodies.
  - AllRequest: ID for exceptions applied to all requests.
  - ResponseHeaders: ID for exceptions related to response headers.
  - ResponseBody: ID for exceptions related to response bodies.
  - AllResponse: ID for exceptions applied to all responses.

### File: <app>waceappconfig.yaml
- modelids (List): a list of model plugin IDs to be applied in this application. Each ID SHOULD match a modelplugin defined in the main configuration.
- decisionid (String): specifies the ID of the decision plugin to use. This ID should correspond to one in the decisionplugins section of the main configuration.
- options:
  - appname (String): the name of the application. This can be used for identification purposes.

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
