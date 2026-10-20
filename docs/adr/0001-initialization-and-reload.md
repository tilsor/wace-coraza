# ADR 0001: WACE WAF initialization, reload and global state

- **Status:** Proposed
- **Date:** 2026-10-13
- **Scope:** `wace_waf` (this repo), the `coraza-caddy` integration and `ModSecIntl_wace_lib`

## Context

Today, besides building the WAF, `NewWAF` does three things:

1. The first time, it reads `WACE_CONFIG_FILEPATH` (`waceconfig.yaml` by default), creates the metrics and calls `wace.Init`.
2. On later calls, it reads the file again, compares the hash and, if it changed, calls `wace.Reload`.
3. It reads `gConfig`, an unsynchronized global `*generalConfig`, to build the WAF config.

This design has known problems:

| Problem | Location |
|---|---|
| `newGC.hash` is never assigned, so every `NewWAF` after a change reloads again | `wace_waf.go:178` |
| `gConfig` is assigned before the init succeeds; if it fails, the next `NewWAF` finds a half-built `gConfig` | `wace_waf.go:112` |
| The error from `setDefaultPlugins` is ignored (silent fail-open) | `wace_waf.go:136`, `wace_waf.go:176` |
| Race on `gConfig`: it is read on every request while a `NewWAF` may replace it | `wace_waf.go:825` |
| Exception ID mismatch: the exceptions WAF is built with the IDs of that moment, but `exceptionActiveModels` reads the current IDs. A reload that changes `exception_ids` silently disables every model | `wace_waf.go:825`, `wace_config.go:420` |
| `LoadConfigFromGeneralConfig` receives `g` but reads `gConfig.earlyBlocking` | `wace_config.go:177` |
| WAFs created before a reload keep referencing models and decisions that may no longer exist | — |
| The logger is set separately (`SetLogger`) and only reaches the lib on the next `Init` or `Reload` | `wace_waf.go:76` |

In addition, the Caddy integration needs an explicit hook to signal that a configuration reload happened and to pass Caddy's logger. It has none today.

### How Caddy uses this package

In `coraza-caddy/coraza.go`:

- `Provision` creates the WAF through a `caddy.UsagePool`, keyed by a hash of the directives, the app config and the exceptions file. If the key did not change, it **reuses the existing WAF**.
- On a Caddy reload, the new instances are provisioned first and the old ones are cleaned up afterwards. There is a window in which both coexist.
- There is one `Provision` per use of the `waf` handler. A config with N protected routes calls it N times on every reload.
- Caddy registers modules in Go's `init()`. Every command of the binary (`caddy version`, `list-modules`, `fmt`, `adapt`, `validate`) imports and initializes every package.

### What the lib does (`55db536`)

- `wace.Init(mp, conf, logger)` fails if the lib is already initialized. It opens the NATS connection and loads the plugins with `plugin.Open`.
- `wace.Reload(mp, conf, logger)` rejects a change of `nats_url` and reloads **every** plugin.
- The logger can only be changed through `Init` or `Reload`, because `setLogger` is not exported.
- `Init` calls `configstore.SetConfig` before `pluginmanager.New`. If the latter fails, the configstore stays set and `pm` stays nil: a later `Init` returns "already initialized" and a `Reload` probably panics (not verified). `Reload` follows the same pattern with `pm.Reload`.
- `Analyze` with a model that no longer exists logs an error on every request and skips it.

## Decision

### 1. Public API

```go
// NewWAF creates a WAF. If WACE WAF is not initialized yet, it
// initializes it first with the current logger.
func NewWAF(config coraza.WAFConfig) (*WaceWAF, error)

// Reload re-reads the WACE general configuration and applies it with
// logger. If WACE WAF is not initialized yet, it initializes it.
func Reload(logger *slog.Logger) error

// ConfigVersion identifies the part of the current general
// configuration that WAFs are built with.
func ConfigVersion() string

// SetLogger replaces the logger, without reading the configuration.
func SetLogger(l *slog.Logger)
```

- **`Init` is not exported.** Initialization is an internal detail of the package.
- **The file path is not part of the interface.** It is still resolved from `WACE_CONFIG_FILEPATH` or the default.
- If `logger` is nil, `slog.Default()` is used, as in `SetLogger` and in the lib.
- **`SetLogger` stays.** It is not the same as a reload: it only changes the logger, without reading the file or initializing anything. Once the lib exports its own `SetLogger`, our `SetLogger` passes the logger to it immediately; today the lib only gets it on the next `Init` or `Reload`. Internally, a `Reload` with no config changes does the same as `SetLogger`.

### 2. Lazy initialization in `NewWAF` or `Reload`, not in Go's `init()`

Initialization is done by an **unexported** function (`initialize`). It is triggered by the first call to `NewWAF` or `Reload`, whichever comes first. It does **not** run in the package's Go `init()`.

- **`NewWAF` alone is enough** to use WACE WAF without reloads: the first call initializes with the logger set by `SetLogger` (or `slog.Default()`), and the following ones use the current configuration.
- **`Reload` is only needed to apply changes** to `waceconfig.yaml` without restarting the process. `NewWAF` never reloads: in Caddy it is not called when the pool reuses a WAF, so it cannot be the reload point (see *Analysis: WAF reuse in the Caddy pool*).
- In **Caddy**, `Provision` calls `Reload(logger)` before looking up the pool. The first call initializes with Caddy's logger, and its errors surface as `Provision` errors.
- If the init fails, the global state is left unchanged and the next `NewWAF` or `Reload` retries it. The retry depends on the lib fix described in *Consequences*.

### 3. `Reload` compares the parsed configuration, not the file

`Reload` parses the YAML and hashes a canonical serialization of the whole parsed configuration (for example, `json.Marshal` of the struct, which sorts map keys). Comments, formatting and key order do not count as changes.

| State | Config unchanged (same hash) | Config changed |
|---|---|---|
| Not initialized | internal init with `logger` | internal init with `logger` |
| Initialized | Only the loggers are replaced. **Plugins are not reloaded** | `wace.Reload` with the new config and `logger`, and the new snapshot is published |

The hash covers every field, including plugin parameters: a changed threshold has to reach the lib through `wace.Reload`. Since Caddy calls `Reload` N times per reload (once per `Provision`), the hash makes calls 2..N no-ops.

### 4. `exception_ids` and `crs_version` cannot change on reload

Both are fixed for the life of the process. A `Reload` whose `exception_ids` or `crs_version` differ from the current ones is **rejected** with an error that says the change needs a restart, and the previous configuration is kept, the same way the lib rejects a change of `nats_url`. The check runs before the lib gets the configuration, so a rejected `Reload` changes nothing.

- **`exception_ids`:** the ids only have to avoid colliding with the rules of the exceptions file, which does not reference them, so they rarely change. Making them fixed removes any chance of WAFs with different exception rule ids coexisting, in the Caddy pool or during the grace window.
- **`crs_version`:** today it only selects the CRS-specific rules `getConfigRules` adds; with future CRS versions it will decide which evaluation rules change. That is a deployment change, not something to switch on running WAFs.

In Caddy, the error fails the `Provision` of the new config, so Caddy keeps running the old config with the old WAFs (step 3 of *Lifecycle of a Caddy config load*). **Every later Caddy reload fails the same way**, even one that only changes the Caddyfile, until `waceconfig.yaml` is reverted or Caddy is restarted. The error message has to say so.

### 5. `ConfigVersion` hashes only what WAFs are built with

`ConfigVersion` returns a hash of the snapshot fields that change how a WAF is built or validated:

- the default models (non-training, by type) and the default decision;
- `early_blocking` and `blocking`;
- the ids, types and `training` flags of the existing model plugins, and the ids and `training` flags of the decision plugins, which validate the app config in `NewWAF`.

Plugin parameters, timeouts, `otel_url`, `nats_url` and the other fields the lib applies live are left out, so changing them does not rebuild the WAFs. `exception_ids` and `crs_version` are left out because they cannot change (decision 4). Slices are sorted before hashing so the order in the file does not count. Before initialization it returns an empty string.

Caddy adds it to the pool key after calling `Reload` (option 1 of the pool analysis).

### 6. Atomic global state, built in full

- `gConfig` becomes an `atomic.Pointer[generalConfig]`.
- A `sync.Mutex` serializes `initialize` and `Reload`. Requests never take the mutex, and `NewWAF` only takes it while WACE WAF is not initialized.
- The new config is built in full before being published: `LoadConfig`, `setDefaultPlugins` **with its error checked**, the hashes, metrics, and `wace.Init`/`wace.Reload`. Only then is the `Store` done. If any step fails, whatever was created (for example, the new metrics) is discarded and the error is returned.
- The default plugins are computed from the parsed YAML before the lib gets the configuration, so a configuration without a valid default decision is rejected without touching the lib.

### 7. Each WAF keeps a snapshot of the config

- `NewWAF` does **a single** `gConfig.Load()` and stores the pointer in `WaceWAF`.
- `exceptionActiveModels`, `LoadExceptionsDirectives`, `LoadConfigFromGeneralConfig` and `getConfigRules` use that snapshot, never the global.

This way a WAF always sees the same models and decisions it was built with, and the race in the hot path is removed.

### 8. The partial reload risk is accepted and documented

A `Reload` applied during a Caddy load that later fails is not undone (see *Risk: partial reload*). This is accepted: `Reload` logs every applied change, and the risk is documented in the `coraza-caddy` README.

## Analysis: WAF reuse in the Caddy pool

### The problem

`coraza-caddy` shares WAFs through a `caddy.UsagePool` (introduced by upstream PR #268, "share WAF instances across reloads"). The key is a hash of:

- the `directives` text and the `include` paths;
- the `load_owasp_crs` flag;
- the resolved app config (its content);
- the **path** of `wace_exceptions_file`.

On a Caddy reload, the new instance's `Provision` happens before the old one's `Cleanup`. If the key did not change, `LoadOrNew` returns the existing WAF and `NewWAF` is not called.

With the snapshot from decision 7, everything a WAF takes from `waceconfig.yaml` is fixed when it is built:

| Snapshot data | Effect on the WAF |
|---|---|
| `crs_version` | Which rules are compiled. It cannot change on reload (decision 4) |
| `exception_ids` | The IDs of the `SecAction`s compiled into the exceptions WAF and the ones `exceptionActiveModels` reads. They cannot change on reload (decision 4) |
| Non-training models and the default decision | The models and the decision when there is no app config |
| `early_blocking`, `blocking` | The same, when there is no app config |
| Existing models and decisions | They validate the app config in `NewWAF` |

If `waceconfig.yaml` changes but the Caddyfile does not, `Reload` updates the lib, but the reused WAF keeps the old snapshot **until the next Caddyfile change**, not only during the grace window.

The same problem exists, without WACE, for the **content** of files referenced by path: `include`, the `Include`s inside `directives`, and `wace_exceptions_file`. Editing the exceptions file and reloading Caddy does not apply it. Some of the solutions below also cover this case.

### Constraints

- Building a WAF with CRS is expensive (parsing and compiling hundreds of rules, plus the corresponding memory). The pool exists to avoid that when nothing changed.
- Caddy serializes config loads, so the `Provision`s of one load never run in parallel with a `Reload` from another.
- The public API the team wants to keep is minimal: `Reload(logger)` and `SetLogger`.

### Options

#### 1. Export `ConfigVersion()` and add it to the pool key

`wace_waf` exports `ConfigVersion() string`, which returns an identifier of the current snapshot. In `Provision`, Caddy calls `Reload(logger)` and then adds `ConfigVersion()` to the key.

- **Pros:**
  - It is precise: WAFs are only rebuilt when the general config changed.
  - It is a few lines of change in Caddy.
  - The WAF can also expose its snapshot's version, so Caddy can check that the built WAF matches the key.
- **Cons:**
  - It adds a function to the public API.
  - If the version is the file hash, changing a comment or a plugin parameter that does not affect the WAF (for example, a model threshold) also rebuilds every WAF. This is mitigated by computing the version only from the fields in the table.
  - It does not solve the problem of files referenced by path.

#### 2. `Reload` returns `(changed bool, err error)` and Caddy keeps a counter

Caddy keeps a global counter that it increments when `Reload` returns `changed == true`, and adds it to the key.

- **Pros:** it does not add a new function.
- **Cons:**
  - It changes the signature of `Reload`.
  - The version lives in Caddy, which has to rebuild it from events. If someone calls `Reload` from elsewhere, the counter gets out of sync.
  - In practice it is option 1 with more coupling.

#### 3. `WaceWAF` rebuilds itself

`WaceWAF` keeps its original `WAFConfig` and detects that its snapshot is stale, for example when creating a transaction. It then rebuilds the inner WAFs (main and exceptions) and swaps them through an atomic pointer.

- **Pros:**
  - It is transparent to Caddy and to any other integration.
  - WAFs no longer need to be recreated after a `Reload` (it also solves point 3 of *Consequences*).
- **Cons:**
  - It breaks Coraza's premise that a WAF is immutable.
  - The rebuild compiles CRS: if done in the hot path, the first request after the reload pays that cost. If done in the background, it has to be coordinated and deduplicated across every WAF.
  - A rebuild error (for example, an app config that references a removed model) has nowhere to be returned: it can only be logged while the old WAF keeps running, and Caddy never finds out.
  - It is the most complex option to implement and to test.

#### 4. Caddy hashes file contents into the key

Caddy reads and hashes the content of `waceconfig.yaml`, of the `include`s and of `wace_exceptions_file`.

- **Pros:**
  - It solves the general problem of files referenced by path, not only WACE's.
  - It adds no API to `wace_waf`.
- **Cons:**
  - Caddy would have to replicate how the `waceconfig.yaml` path is resolved (`WACE_CONFIG_FILEPATH`), which is exactly what was decided not to expose.
  - The `Include`s inside `directives` require interpreting the directives.
  - What matters is the config the lib *accepted*, not the file's: if `Reload` fails, the key changes anyway and a new WAF is built with the old snapshot.

#### 5. Do not reuse WAFs across reloads

The key includes an identifier of the config load, or the pool is removed. Every Caddy reload rebuilds every WAF. With a load identifier, deduplication within a single load is kept.

- **Pros:**
  - It is always correct, also for files referenced by path and for rule changes.
  - It is the simplest option.
- **Cons:**
  - The pool's benefit is lost: every reload compiles CRS again for each distinct config, and memory doubles during the grace window.
  - Caddy does not expose a public load identifier. It would have to be derived (for example, from the identity of the `caddy.Context`), which is fragile.

### Comparison

| | Correct on `waceconfig.yaml` changes | Correct on referenced file changes | Cost on each reload with no changes | New API in `wace_waf` | Complexity |
|---|---|---|---|---|---|
| 1. `ConfigVersion()` | Yes | No | None | `ConfigVersion()` | Low |
| 2. `changed` + counter | Yes, if only Caddy calls `Reload` | No | None | `Reload` signature change | Low |
| 3. Self-rebuild | Yes | No | None | None | High |
| 4. Content hash | Partial (fails if `Reload` is rejected) | Partial (does not cover `Include` in `directives`) | Reading and hashing files | None | Medium |
| 5. No reuse | Yes | Yes | Rebuilding every WAF | None | Low |

### Decision

**Option 1**, with the version computed only from the snapshot fields that affect the WAF (decision 5), not from the file hash. This way, changing a plugin parameter, which the lib applies live through `Reload`, does not rebuild the WAFs.

The problem of files referenced by path predates WACE and comes from upstream. It can be handled separately, for example with option 4 limited to `wace_exceptions_file`, which is WACE's own file.

## Analysis: Caddy flows and where `Reload` is triggered

Since `Init` is not exported, initialization and reloads happen when Caddy provisions the module. This section describes in which Caddy flows that happens and in which it does not. It was verified against the code of Caddy v2.11.2, the version `coraza-caddy` uses.

### Lifecycle of a Caddy config load

Every config load, initial or reload, goes through `caddy.changeConfig`, which takes a global lock. Two loads therefore never run in parallel.

1. If the adapted JSON is **identical** to the current one and the load was not forced, it ends with `errSameConfig` and nothing is provisioned.
2. `run(newCfg, start=true)` creates a new `caddy.Context` and provisions every app. The `http` app provisions its servers and routes, and each `waf` handler runs its `Provision`.
3. If any `Provision` fails, the new context is cancelled: the modules already provisioned get `Cleanup` and **the old config keeps running**.
4. If everything was provisioned, the new apps are started, the context is swapped, and only then are the old config's `Stop` and `Cleanup` run.

### Proposed trigger point

In `corazaModule.Provision`, **before** computing the pool key:

```text
Provision(ctx)
  ├─ m.logger = ctx.Logger(m)
  ├─ waceWAF.Reload(slog.New(zapslog.NewHandler(m.logger.Core())))   ← init the first time, reload if changed, logger only otherwise
  ├─ resolveWaceAppConfig()
  ├─ poolKey = computePoolKey() + waceWAF.ConfigVersion()           ← option 1 of the pool analysis
  └─ wafPool.LoadOrNew(poolKey, buildWAF → waceWAF.NewWAF)
```

Caddy's logger is a `*zap.Logger`; it is adapted to `slog` with `go.uber.org/zap/exp/zapslog`.

### Flows

| # | Caddy flow | Is there a `Provision`? | What happens in WACE |
|---|---|---|---|
| 1 | Startup: `caddy run`, `caddy start`, `caddy run --resume`, systemd service | Yes | The first `Provision` calls `Reload`, which triggers the internal init with Caddy's logger. The following `Provision`s only change the logger. If the init fails, the error comes out of `Provision` and **Caddy does not start**. |
| 2 | Reload with a changed Caddyfile: `caddy reload`, `POST /load`, `PATCH`/`PUT` on `/config/...`, SIGUSR1 (if started with `caddy run --config`), `caddy run --watch`, `admin.config.load` with `load_interval` | Yes, for every instance | The first `Provision` calls `Reload`: if `waceconfig.yaml` changed, it is applied; otherwise only the logger changes. Pooled WAFs are reused or not depending on the key. |
| 3 | Reload with an **unchanged** Caddyfile (any of the mechanisms in 2) | **No** (`errSameConfig`) | **`Reload` is not called.** If only `waceconfig.yaml` changed, the change is not applied. |
| 4 | Forced reload: `caddy reload --force` or `POST /load` with `Cache-Control: must-revalidate` | Yes | Same as 2. **It is the only way to apply a change that is only in `waceconfig.yaml`.** |
| 5 | Reload that fails in another module, after our `Provision` already called `Reload` | Yes, but the load is cancelled | The lib and `gConfig` already have the new config, but the WAFs still serving traffic are the old ones, with the old snapshot. See *Risk: partial reload*. |
| 6 | `caddy validate` and `caddy adapt --validate` | Yes, in a new, independent process, followed by `Cleanup` | The full init runs from scratch. It does not conflict with the server's `Init` because each process has its own state. See *Detail: `caddy validate`*. |
| 7 | Shutdown: `caddy stop`, SIGINT, SIGTERM, `POST /stop` | No (`Stop` and `Cleanup`) | The pool destroys the WAFs and calls their `Close`. **The WACE engine is not closed** (covered by the shutdown ADR). |
| 8 | `caddy version`, `list-modules`, `fmt`, `adapt` without `--validate`, `environ`, `build-info` | No | No WACE code runs. This is the main difference from initializing in Go's `init()`. |

Outside Caddy, the first `NewWAF` initializes WACE WAF with the logger set by `SetLogger`. An integration that wants to apply changes without restarting calls `Reload(logger)` whenever its own lifecycle requires it.

### Observations

**Changes only in `waceconfig.yaml` (flows 3 and 4).** Caddy decides whether to reload by comparing its own JSON, and `--watch` only watches the Caddyfile. A change that is only in WACE's YAML needs `caddy reload --force`. This must be documented in the `coraza-caddy` README. Having the module watch the YAML on its own does not help: it would call `Reload` outside a Caddy load, and the pooled WAFs would not be rebuilt, except with option 3 of the pool analysis.

**N calls per load.** Each `waf` handler is provisioned separately, so `Reload` is called once per use of the handler. The first call does the work and the rest only compare the hash and change the logger. Since every logger comes from the same module, the last one winning has no visible effect.

### Detail: `caddy validate` (flow 6)

`caddy validate` and `caddy adapt --validate` are CLI commands that **do not talk to the running Caddy**: they do not use the admin API. Each one starts a new process of the binary, which:

1. reads and adapts the Caddyfile;
2. calls `caddy.Validate(cfg)`, which provisions the whole config (without starting the servers) and then calls `Cleanup` on everything;
3. prints "Valid configuration" and exits.

**The admin API has no validation endpoint.** Caddy v2.11.2 exposes `/load`, `/adapt`, `/config/`, `/id/`, `/stop`, `/metrics`, `/reverse_proxy/upstreams` and the `pprof` ones. `/adapt` only converts the Caddyfile to JSON, without provisioning, so it runs no WACE code. Through the API, the only way to "try" a config is `/load`, which **applies it**: it is flow 2 (or 4 with `Cache-Control: must-revalidate`), and if it fails, flow 5, with the partial reload risk.

**It does not fail because of a second init.** WACE's state (`gConfig`, the lib's configstore, the plugin manager) lives in process memory. The `validate` process starts with everything empty, so the `Reload` of the first `Provision` performs a normal init; the server's `wace.Init` lives in another process. Even if `caddy.Validate` were called inside the server process (Caddy does not do this in any flow), it would not fail either: `Reload` only calls `wace.Init` if the package is not initialized; if it is, it takes the reload path.

**Side effects of the init in that process.** The init does more than validate:

- **It reads `waceconfig.yaml` according to the `validate` process's environment.** If `WACE_CONFIG_FILEPATH` is set for the service (for example, in the systemd unit) but not in the shell `caddy validate` runs from, the default path is used, relative to the current directory. Validation fails even though the server's config is correct, or it validates a different file. `--envfile` allows loading the same environment.
- **It connects to NATS.** For each async or remote model, the lib subscribes to the model's queue with a *queue group* (`ModelProcessHandler`), and to the results queue. While the `validate` process is alive, **NATS may deliver to it model inputs sent by the real server**. If the process exits before processing them, those inputs are lost and the server's transaction waits until `model_timeout`. The window is short (the time validation takes), and today there is no engine shutdown that drains the subscriptions before exiting.
- **It loads the plugins** (`plugin.Open`) and runs their initialization. If a plugin has external side effects on startup, they happen too.
- **It creates the metrics exporter** if `otel_url` is set, and may send some metrics with the same `service.name` as the server.

**Decision:** for now, NATS input theft is accepted as a **known risk** and documented; it is not mitigated in this ADR. The `coraza-caddy` README recommends avoiding `caddy validate` against the same NATS instance in production when there are async or remote models, or running it at a low-traffic time. If mitigation is needed later, there are two paths:

- The lib does not start the NATS handlers during init, but in a later step that `caddy validate` does not run (for example, the `Start` of the `wace` app).
- The engine shutdown drains the subscriptions, and `Cleanup` calls it when the last WAF is destroyed.

### Risk: partial reload (flow 5)

`Reload` modifies process-global state (the lib and `gConfig`), but the Caddy load is transactional: if it fails, Caddy discards the new config and keeps the old one. Our `Reload` is not undone. As a result, the old WAFs, with their old snapshot, coexist with a lib that already has the new config:

- If a model was removed, the lib logs "plugin not found" on every request and skips it.
- If a decision was removed, `CheckTransaction` returns an error.
- If a plugin parameter changed, it is applied even though the Caddy load failed.

The state is corrected on the next successful load. Options:

- **(a) Accept and document it.** Log every change `Reload` applies, so there is a record. **Chosen** (decision 8).
- **(b) Two-phase reload.** Validate and prepare in `Provision`, and apply in a later phase only if the whole load succeeded. It requires the lib to split validation from application (today `wace.Reload` does both) and a Caddy hook that runs after everything was provisioned. An app's `Start` works, but the start order between apps is not guaranteed, so the `http` app could start serving before the config is applied.

### Alternative: a `wace` Caddy app

Instead of calling `Reload` from the handler, `coraza-caddy` would register an app (`caddy.App`) with ID `wace`. Handlers get it with `ctx.App("wace")`, which provisions it only once per load.

| | From the handler's `Provision` | `wace` app |
|---|---|---|
| `Reload` calls per load | N (one does the work) | 1 |
| Natural place for engine shutdown | None: a reference counter is needed | The app's `Stop`/`Cleanup` |
| Place for a second reload phase | No | `Start` (with the caveat about app order) |
| Change in `coraza-caddy` | A few lines | A new module and its registration |

**Recommendation:** call `Reload` from the handler's `Provision`. The `wace` app is evaluated in the shutdown ADR, which is where its advantages (`Stop`, `Cleanup` and the second phase) become necessary.

## Alternatives considered

### A. Initialize in the package's Go `init()` (rejected)

Its advantage is that the init is "invisible": no consumer has to call it. However:

- **It runs on every Caddy command.** `caddy version` or `caddy fmt` would read the YAML, open NATS and load `.so` plugins. With the default path, `waceconfig.yaml` is resolved against the current directory, so it would fail in almost any directory.
- **It cannot return errors.** It would have to either `panic`, which breaks the whole binary even when the WAF is not used, or store the error to return it from `NewWAF`, which delays the error and leaves a half-done init's resources open.
- **It does not have Caddy's logger.** The logs of the init and of plugin loading would go to `slog.Default()`, outside Caddy's logging pipeline.
- **It complicates the tests.** It runs before `TestMain`, so the tests that currently change `configFilePath` and reset `gConfig` would have to undo an init that already happened.

### B. Export `Init(path)` and `Reload(path)` (rejected)

It is explicit, but it adds API surface and forces deciding who calls `Init` in Caddy, where there is no single "startup" other than the first `Provision`. With the lazy init, `NewWAF` and `Reload` already cover that case.

### D. Initialization only through `Reload` (rejected)

`NewWAF` would fail until a `Reload` initializes WACE WAF, so there is a single initialization path and forgetting `Reload` fails at startup. Rejected because it forces every integration to call `Reload` even when it does not need reloads, and the main cost of the lazy init (a second entry point) is small: both paths call the same `initialize` under the same mutex.

### C. Keep the implicit reload inside `NewWAF` (rejected)

It mixes building a WAF with mutating global state, and in Caddy it would not trigger if the pool reuses the WAF. It is also the cause of several bugs in the table.

## Consequences

### Positive

- The bugs at `wace_waf.go:112`, `:136`, `:176`, `:178`, `:825`, and at `wace_config.go:177` and `:420` are fixed.
- Importing the package has no side effects.
- Integrations that do not need reloads only call `NewWAF`. Caddy has a single entry point (`Reload(logger)` in `Provision`) that serves both the first startup and reloads.
- Changing only the logger, or comments and formatting of the YAML, does not reload the plugins. Changing only plugin parameters does not rebuild the WAFs.

### Negative and follow-up work

1. **Changes in the lib (`ModSecIntl_wace_lib`):**
   - Export `SetLogger(l *slog.Logger)` so the logger can be changed without reloading the plugins. Without it, every `Reload` would have to call `wace.Reload` and would reload the plugins N times per Caddy reload.
   - Make `Init` and `Reload` atomic: do not leave the configstore updated if `pluginmanager.New` or `pm.Reload` fail. Without this, a failed init cannot be retried.
2. **The Caddy WAF pool does not see `waceconfig.yaml` changes.** See *Analysis: WAF reuse in the Caddy pool*.
3. **Old WAFs during the grace window.** They keep using their snapshot. If a model was removed, the lib logs "plugin not found" per request and skips it; for a removed decision, `CheckTransaction` returns an error. This is acceptable if the window is short. It is documented that, after a `Reload` that changes the config, WAFs must be recreated.
4. **Accepted risk, `caddy validate` and NATS:** a `caddy validate` process may receive async or remote model inputs sent by the server and lose them when it exits. See *Detail: `caddy validate`*. It is documented in the `coraza-caddy` README.
5. **Behavior changes for consumers:** `NewWAF` no longer applies changes to `waceconfig.yaml`; integrations that relied on that have to call `Reload`. Changing `exception_ids` or `crs_version` now requires a restart. Both have to be called out in the release notes.
6. **Tests:** the ones that currently do `gConfig = nil` need a reset helper that clears the atomic pointer. The lib's state cannot be reset, so those tests still depend on running in the same process, as today.

## Open questions

1. **Shutdown:** this ADR does not define the shutdown API for the final metrics flush (pending from the list). With the Caddy pool, the engine shutdown would have to happen when the last WAF is destroyed, and the lib has no `Close` either. The proposal is to address it in a separate ADR, together with the pending lib change so that closing a transaction cancels the in-flight models.
