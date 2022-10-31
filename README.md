# ip2proxy

Plugin for getting information from ip2proxy database and pass it to request headers

## Configuration

To configure this plugin you should add its configuration to the Traefik dynamic configuration as explained [here](https://docs.traefik.io/getting-started/configuration-overview/#the-dynamic-configuration).
The following snippet shows how to configure this plugin with the File provider in TOML and YAML:

Static:

```yaml
experimental:
  pilot:
    token: xxx

  plugins:
    ip2proxy:
      modulename: github.com/benbut/traefik-plugin-ip2proxy
      version: v0.1.0
```

Dynamic:

```yaml
http:
  middlewares:
   my-plugin:
      plugin:
        ip2location:
          filename: /path/to/database.bin
          fromHeader: X-User-IP # optional
          disableErrorHeader: false
          headers:
            CountryShort: X-PROXY-CountryShort
            CountryLong: X-PROXY-CountryLong
            Region: X-PROXY-Region
            City: X-PROXY-City
            ISP: X-PROXY-ISP
            Domain: X-PROXY-Domain
            IsProxy: X-PROXY-IsProxy
            ProxyType: X-PROXY-ProxyType
            UsageType: X-PROXY-UsageType
            ASN: X-PROXY-ASN
            AS: X-PROXY-AS
            LastSeen: X-PROXY-LastSeen
            Threat: X-PROXY-Threat
            Provider: X-PROXY-Provider
```

### Options

#### Filename (`filename`)

*Required*

The path to ip2proxy database file (in binary format)

#### FromHeader (`fromHeader`)

*Default: empty*

If defined, IP address will be obtained from this HTTP header

#### DisableErrorHeader (`disableErrorHeader`)

*Default: false*

If `false`, any errors will be placed to the `X-IP2PROXY-ERROR` http header. Set to `true` for disable.

#### Headers (`headers`)

*Default: empty*

Define the HTTP Header name if you want to pass any of the parameters

### Errors

If any error occurred, this error will be placed to X-IP2PROXY-ERROR header
