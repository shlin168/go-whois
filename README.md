# Go Whois

[![Actions Status](https://github.com/shlin168/go-whois/actions/workflows/go.yml/badge.svg)](https://github.com/shlin168/go-whois/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/shlin168/go-whois/branch/master/graph/badge.svg)](https://codecov.io/gh/shlin168/go-whois)

Provide WHOIS [library](#Library), [command line tool](#Command-Line-Tool) and [server with restful APIs](#Server) to query whois information for domains and IPs.

It's also available to specify whois server to query if known.

> :warning: There're diverse WHOIS formats for domains (especially `cctld`). It's hard to precisely parse all the information from rawtext. It is suggested that either adding `Parser` in [domain](whois/domain) or parse again with self-defined method after getting general WHOIS response.

## Library
### Install
```
go get github.com/shlin168/go-whois
```
### Example
```go
package main

import (
    "os"
    "context"
    "fmt"
    "time"
    "github.com/shlin168/go-whois/whois"
)

func main() {
    ctx := context.Background()
    // client default timeout: 5s,
    // client with custom timeout: whois.NewClient(whois.WithTimeout(10*time.Second))
    client, err := whois.NewClient()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    // query domain
    qDomain := "www.google.com"
    whoisDomain, err := client.Query(ctx, qDomain)
    if err == nil {
        fmt.Println("rawtext:", whoisDomain.RawText)
        fmt.Println("from whois server:", whoisDomain.WhoisServer)
        fmt.Printf("parsed whois: %+v\n", whoisDomain.ParsedWhois)
        if whoisDomain.IsAvailable != nil {
          fmt.Println("available:", *whoisDomain.IsAvailable)
        }
    }

    // query IP
    qIP := "1.1.1.1"
    whoisIP, err := client.QueryIP(ctx, qIP)
    if err == nil {
        fmt.Println("rawtext:", whoisIP.RawText)
        fmt.Println("from whois server:", whoisIP.WhoisServer)
        fmt.Printf("parsed whois: %+v\n", whoisIP.ParsedWhois)
    }
}
```
Note: `NewClient` fetch and parse [whois-server-xml](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml) when invoked. To avoid fetching file every time when initializing client, changed to use method below:
```go
serverMap, err := whois.NewDomainWhoisServerMap(whois.WhoisServerListURL)
if err != nil {
    ...
}
client := whois.NewClient(whois.WithServerMap(serverMap))
```

## Command Line Tool
### Build
```bash
go build -o $PWD/bin ./cmd/whois
```
### Usage
To query whois domain/ip
```bash
./bin/whois -q google.com
```
```bash
./bin/whois -q 1.1.1.1
```
Query from sepecified whois server
```bash
./bin/whois -q aaa.aaa -server whois.nic.aaa
```
Query with timeout (default: `5s`)
```bash
./bin/whois -q google.com -timeout 10s
```

## Server
### Build
```bash
go build -o $PWD/bin ./cmd/server
```
### Usage
Start server, default listen on `:8080` port, and prometheus metrics show in `:6060`
```bash
./bin/server
```
Run `./bin/server -h` to check other arguments

### API
`POST /whois`

Query with domain/ip
```
{
  "query": "www.google.com"
}
```
```
{
  "query": "1.1.1.1"
}
```
Query with domain and also query ip from resolver
```
{
  "query": "www.google.com",
  "ip": true
}
```
Query from sepecified whois server
```
{
  "query": "aaa.aaa",
  "whois_server": "whois.nic.aaa"
}
```
```
{
  "query": "120.111.10.123",
  "whois_server": "whois.apnic.net"
}
```

#### HTTP Response Code
  * `200`: found
  * `404`: not found, which means response rawtext contains keywords that are regard as WHOIS not found
      * Method: Try to fetch keywords([domain](./whois/domain/parser.go#L127)/[ip](./whois/ip/parser.go#L77)) in rawtext
  * `400`: invalid input, wrong request format or error when getting public suffixs for domain
  * `408`: whois server not response after `N`(timeout, default `5s`) seconds
  * `500`: internal error

## PublicSuffix for domain
Input domain is parsed by [`publicsuffix`](https://pkg.go.dev/golang.org/x/net/publicsuffix). Final public suffixs to query WHOIS server are composed by the result of `EffectiveTLDPlusOne(domain)` and `PublicSuffix(domain)`:
1. Append `EffectiveTLDPlusOne(domain)` to query list if error is `nil`
2. Check `PublicSuffix(domain)` result, if it's not ICANN managed domain and not fit *specific `<= 3` rule, only query `PublicSuffix(domain)`, else query both.
3. If level of `PublicSuffix(domain)` is larger than 2, append `level=n-1` domain to query list until it reaches `level=2`.
    * E.g, `PublicSuffix("abc.ipfs.dweb.link") = "ipfs.dweb.link"` which level equals to 3. Append `dweb.link` to query list
4. Query whois in order, return **the longest domain** that can be found.

* specific `<= 3` rule: all length of items in public suffix are no more than 3
    * hit: `co.uk`, `jpn.com`, `net.ua`
    * not hit: `github.io`, `zhitomir.ua`

> All the domains that query whois contains at least 2 levels.

| Input              | ps + 1             | ps             | ICANN | <= 3  | ps list to query WHOIS      | Found           | Result domain   |
|--------------------|--------------------|----------------| ------|-------|-----------------------------| ----------------| ----------------|
| abc.github.io      | abc.github.io      | github.io      | false | false | [github.io]                 | github.io       | github.io       |
| frolic.yalta.ua    | frolic.yalta.ua    | yalta.ua       | true  | false | [frolic.yalta.ua, yalta.ua] | BOTH            | frolic.yalta.ua |
| bruker.co.ua       | bruker.co.ua       | co.ua          | false | true  | [bruker.co.ua, co.ua]       | BOTH            | bruker.co.ua    |
| registry.co.com    | registry.co.com    | co.com         | false | true  | [registry.co.com, co.com]   | co.com          | co.com          |
| abc.ipfs.dweb.link | abc.ipfs.dweb.link | ipfs.dweb.link | false | false | [ipfs.dweb.link, dweb.link] | dweb.link       | dweb.link       |
| www.google.com     | google.com         | com            | true  | false | [google.com]                | google.com      | google.com      |
| www.GOOGLE.com     | GOGGLE.com         | com            | true  | false | [google.com]                | google.com      | google.com      |
| org                | x                  | x              | true  | true  | x                           | x               | x               |

> PublicSuffix does not modify the case, we convert the result to lowercase and query for consistency although domain name is not case sensitive. While `query` field in `response` and `access log` keep the case.

## Prometheus Metrics
### HTTP requests
* `whois_http_request_total{code=...}` (counter) The amount of requests per HTTP status code
* `whois_http_request_in_flight` (gauge) A gauge of requests currently being served by the wrapped handler
* `whois_http_request_duration_seconds` (histogram) A histogram of latencies for requests

### Service
#### Counter
* `whois_response_total{resp_by=...,resp_type=...,type=...}` (counter) The amount of response from per input_type, per components and per result type for queries
  * `resp_by` includes
    * `public_suffix`
    * `realtime`
    * `none`
  * `resp_type` includes
    * `found`
    * `not_found`
    * `error`
    * `timeout`
  * `type` includes
    * `domain`
    * `ip`
* `whois_nslookup_total{status=...}` (counter) The amount of return status when doing ip lookup for domains
  * `status` includes
    * `found`
    * `not_found`
    * `error`

## How to know which whois server to query for input
* For domains, whois server is fetched from [whois-server-xml](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml)
* For IPs, query `whois.arin.net` and get the next whois server to query
