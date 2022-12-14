package traefik_plugin_ip2proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type httpHandlerMock struct{}

func (h *httpHandlerMock) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestIP2Proxy(t *testing.T) {
	var err error

	i := &IP2Proxy{
		next: &httpHandlerMock{},
		headers: Headers{
			CountryShort: "X-GEO-Country",
		},
	}
	i.db, err = OpenDB("IP2PROXY-LITE-PX11.BIN")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/some/path", nil)
	req.RemoteAddr = "4.0.0.0:34000"
	rw := httptest.NewRecorder()

	i.ServeHTTP(rw, req)

	v := req.Header.Get("X-GEO-Country")
	if v != "US" {
		t.Fatal("unexpected value", v)
	}
}
