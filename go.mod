module gitlab.fing.edu.uy/gsi/pgrado-wace/poc

go 1.22.2

require github.com/corazawaf/coraza/v3 v3.1.0

require (
	github.com/corazawaf/libinjection-go v0.1.3 // indirect
	github.com/magefile/mage v1.15.0 // indirect
	github.com/petar-dambovaliev/aho-corasick v0.0.0-20230725210150-fb29fc3c913e // indirect
	github.com/tidwall/gjson v1.17.1 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.1 // indirect
	github.com/tilsor/ModSecIntl_logging v1.0.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sync v0.6.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	rsc.io/binaryregexp v0.2.0 // indirect
)

require gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core v0.0.0-20240805232631-6427ad0a6aa8

replace gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core => gitlab.fing.edu.uy/gsi/pgrado-wace/ModSecIntl_wace_core.git v0.0.0-20240805232631-6427ad0a6aa8
