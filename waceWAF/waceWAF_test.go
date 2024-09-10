package waceWAF

import (
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestNewWAF(t *testing.T) {
	wafConfig := coraza.NewWAFConfig()
	waf, err := NewWAF(wafConfig)
	if err != nil {
		t.Errorf("Error creating WAF: %v", err)
	}
	tx := waf.NewTransaction()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	txW, ok := tx.(WaceTransaction)
	if !ok {
		t.Errorf("Error casting to WaceTransaction")
	}
	expectedRequestLine := "GET http://localhost:8090 HTTP/1.1"
	gotRequestLine := *txW.requestLine
	if expectedRequestLine != gotRequestLine {
		t.Errorf("Error processing URI: Expected: %s, Got: %s", expectedRequestLine, gotRequestLine)
	}
}