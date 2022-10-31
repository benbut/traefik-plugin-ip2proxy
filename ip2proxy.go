package traefik_plugin_ip2proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

// Headers part of the configuration
type Headers struct {
	CountryShort       string `json:"country_short,omitempty"`
	CountryLong        string `json:"country_long,omitempty"`
	Region             string `json:"region"`
	City               string `json:"city"`
	Isp                string `json:"isp"`
	Domain             string `json:"domain"`
	IsType             string `json:"isproxy"`
	ProxyType          string `json:"proxytype"`
	Usagetype          string `json:"usagetype"`
	Asn                string `json:"asn"`
	As                 string `json:"as"`
	LastSeen           string `json:"lastseen"`
	Threat             string `json:"threat"`
	Provider           string `json:"provider"`
}

// Config the plugin configuration.
type Config struct {
	Filename           string  `json:"filename,omitempty"`
	FromHeader         string  `json:"from_header,omitempty"`
	Headers            Headers `json:"headers,omitempty"`
	DisableErrorHeader bool    `json:"disable_error_header,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// IP2Proxy plugin.
type IP2Proxy struct {
	next               http.Handler
	name               string
	fromHeader         string
	db                 *DB
	headers            Headers
	disableErrorHeader bool
}

// New created a new IP2Proxy plugin.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	db, err := OpenDB(config.Filename)
	if err != nil {
		return nil, fmt.Errorf("error open database file, %w", err)
	}

	return &IP2Proxy{
		next:               next,
		name:               name,
		fromHeader:         config.FromHeader,
		db:                 db,
		headers:            config.Headers,
		disableErrorHeader: config.DisableErrorHeader,
	}, nil
}

func (a *IP2Proxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip, err := a.getIP(req)
	if err != nil {
		if !a.disableErrorHeader {
			req.Header.Add("X-IP2PROXY-ERROR", err.Error())
		}
		a.next.ServeHTTP(rw, req)
	}

	record, err := a.db.Get_all(ip.String())
	if err != nil {
		if !a.disableErrorHeader {
			req.Header.Add("X-IP2PROXY-ERROR", err.Error())
		}
		a.next.ServeHTTP(rw, req)
	}

	a.addHeaders(req, &record)

	a.next.ServeHTTP(rw, req)
}

func (a *IP2Proxy) getIP(req *http.Request) (net.IP, error) {
	if a.fromHeader != "" {
		return net.ParseIP(req.Header.Get(a.fromHeader)), nil
	}

	addr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}

	return net.ParseIP(addr), nil
}

func (a *IP2Proxy) addHeaders(req *http.Request, record *IP2Proxyrecord) {
	if a.headers.CountryShort != "" {
		req.Header.Add(a.headers.CountryShort, record.Country_short)
	}
	if a.headers.CountryLong != "" {
		req.Header.Add(a.headers.CountryLong, record.Country_long)
	}
	if a.headers.Region != "" {
		req.Header.Add(a.headers.Region, record.Region)
	}
	if a.headers.City != "" {
		req.Header.Add(a.headers.City, record.City)
	}
	if a.headers.Isp != "" {
		req.Header.Add(a.headers.Isp, record.Isp)
	}
	if a.headers.Domain != "" {
		req.Header.Add(a.headers.Domain, record.Domain)
	}
	if a.headers.IsProxy != "" {
		req.Header.Add(a.headers.IsProxy, record.IsProxy)
	}
	if a.headers.ProxyType != "" {
		req.Header.Add(a.headers.ProxyType, record.ProxyType)
	}
	if a.headers.UsageType != "" {
		req.Header.Add(a.headers.UsageType, record.UsageType)
	}
	if a.headers.Asn != "" {
		req.Header.Add(a.headers.Asn, record.Asn)
	}
	if a.headers.As != "" {
		req.Header.Add(a.headers.As, record.As)
	}
	if a.headers.LastSeen != "" {
		req.Header.Add(a.headers.LastSeen, record.LastSeen)
	}
	if a.headers.Threat != "" {
		req.Header.Add(a.headers.Threat, record.Threat)
	}
	if a.headers.Provider != "" {
		req.Header.Add(a.headers.Provider, record.Provider)
	}
}
