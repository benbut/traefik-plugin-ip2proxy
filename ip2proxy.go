package traefik_plugin_ip2proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

type Headers struct {
	CountryShort string `json:"country_short,omitempty"`
	CountryLong  string `json:"country_long,omitempty"`
	Region       string `json:"region"`
	City         string `json:"city"`
	Isp          string `json:"isp"`
	Domain       string `json:"domain"`
	IsProxy      string `json:"isproxy"`
	ProxyType    string `json:"proxytype"`
	Usagetype    string `json:"usagetype"`
	Asn          string `json:"asn"`
	As           string `json:"as"`
	LastSeen     string `json:"lastseen"`
	Threat       string `json:"threat"`
	Provider     string `json:"provider"`
}

type Config struct {
	Filename           string  `json:"filename,omitempty"`
	FromHeader         string  `json:"from_header,omitempty"`
	Headers            Headers `json:"headers,omitempty"`
	DisableErrorHeader bool    `json:"disable_error_header,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type IP2Proxy struct {
	next               http.Handler
	name               string
	fromHeader         string
	db                 *DB
	headers            Headers
	disableErrorHeader bool
}

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

	record, err := a.db.GetAll(ip.String())

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

func (a *IP2Proxy) addHeaders(req *http.Request, record *ip2proxyRecord) {
	if a.headers.CountryShort != "" {
		req.Header.Add(a.headers.CountryShort, record.countryShort)
	}

	if a.headers.CountryLong != "" {
		req.Header.Add(a.headers.CountryLong, record.countryLong)
	}

	if a.headers.Region != "" {
		req.Header.Add(a.headers.Region, record.region)
	}

	if a.headers.City != "" {
		req.Header.Add(a.headers.City, record.city)
	}

	if a.headers.Isp != "" {
		req.Header.Add(a.headers.Isp, record.isp)
	}

	if a.headers.Domain != "" {
		req.Header.Add(a.headers.Domain, record.domain)
	}

	if a.headers.IsProxy != "" {
		req.Header.Add(a.headers.IsProxy, strconv.FormatFloat(float64(record.isProxy), 'f', 0, 64))
	}

	if a.headers.ProxyType != "" {
		req.Header.Add(a.headers.ProxyType, record.proxyType)
	}

	if a.headers.Usagetype != "" {
		req.Header.Add(a.headers.Usagetype, record.usageType)
	}

	if a.headers.Asn != "" {
		req.Header.Add(a.headers.Asn, record.asn)
	}

	if a.headers.As != "" {
		req.Header.Add(a.headers.As, record.as)
	}

	if a.headers.LastSeen != "" {
		req.Header.Add(a.headers.LastSeen, record.lastSeen)
	}

	if a.headers.Threat != "" {
		req.Header.Add(a.headers.Threat, record.threat)
	}

	if a.headers.Provider != "" {
		req.Header.Add(a.headers.Provider, record.provider)
	}
}
