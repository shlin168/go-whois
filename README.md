# Go Whois

[![Actions Status](https://github.com/shlin168/go-whois/actions/workflows/go.yml/badge.svg)](https://github.com/shlin168/go-whois/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/shlin168/go-whois/branch/master/graph/badge.svg)](https://codecov.io/gh/shlin168/go-whois)

Provides a WHOIS [library](#Library), [command line tool](#Command-Line-Tool), and [server with RESTful APIs](#Server) to query WHOIS information for domains and IP addresses.

You can also specify a WHOIS server to query if known.

> :warning: **Note**: There are diverse WHOIS formats for domains (especially country code top-level domains). It's difficult to precisely parse all information from raw text. We recommend either adding a `Parser` in [domain](whois/domain) or parsing again with a custom method after getting the general WHOIS response.

## Library
### Installation
```bash
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
    // Client default timeout: 5s
    // Client with custom timeout: whois.NewClient(whois.WithTimeout(10*time.Second))
    client, err := whois.NewClient()
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    // Query domain
    qDomain := "www.google.com"
    whoisDomain, err := client.Query(ctx, qDomain)
    if err == nil {
        fmt.Println("Raw text:", whoisDomain.RawText)
        fmt.Println("From WHOIS server:", whoisDomain.WhoisServer)
        fmt.Printf("Parsed WHOIS: %+v\n", whoisDomain.ParsedWhois)
        if whoisDomain.IsAvailable != nil {
          fmt.Println("Available:", *whoisDomain.IsAvailable)
        }
    }

    // Query IP
    qIP := "1.1.1.1"
    whoisIP, err := client.QueryIP(ctx, qIP)
    if err == nil {
        fmt.Println("Raw text:", whoisIP.RawText)
        fmt.Println("From WHOIS server:", whoisIP.WhoisServer)
        fmt.Printf("Parsed WHOIS: %+v\n", whoisIP.ParsedWhois)
    }
}
```
**Note**: `NewClient` fetches and parses [whois-server-xml](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml) when invoked. To avoid fetching the file every time when initializing the client, use the method below:
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
To query WHOIS information for domains or IP addresses:
```bash
./bin/whois -q google.com
```
```bash
./bin/whois -q 1.1.1.1
```
Query from a specified WHOIS server:
```bash
./bin/whois -q aaa.aaa -server whois.nic.aaa
```
Query with custom timeout (default: `5s`):
```bash
./bin/whois -q google.com -timeout 10s
```

## Server
### Build
```bash
go build -o $PWD/bin ./cmd/server
```
### Usage
Start the server (default: listens on port `:8080` and serves Prometheus metrics on `:6060`):
```bash
./bin/server
```
Run `./bin/server -h` to see all available arguments.

### API
`POST /whois`

Query with domain or IP address:
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
Query domain and also resolve its IP address:
```
{
  "query": "www.google.com",
  "ip": true
}
```
Query from a specified WHOIS server:
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

#### HTTP Response Codes
  * `200`: Found - WHOIS information successfully retrieved
  * `404`: Not found - response raw text contains keywords indicating WHOIS record not found
      * Method: Searches for keywords ([domain](./whois/domain/parser.go#L127)/[IP](./whois/ip/parser.go#L77)) in raw text
  * `400`: Bad request - invalid input, wrong request format, or error when getting public suffixes for domain
  * `408`: Request timeout - WHOIS server did not respond within the timeout period (default: `5s`)
  * `500`: Internal server error

## Public Suffix Handling for Domains
Input domains are parsed using [`publicsuffix`](https://pkg.go.dev/golang.org/x/net/publicsuffix). The final public suffixes to query WHOIS servers are composed of the results from `EffectiveTLDPlusOne(domain)` and `PublicSuffix(domain)`:

1. Append `EffectiveTLDPlusOne(domain)` to the query list if the error is `nil`
2. Check the `PublicSuffix(domain)` result:
   - If it's not an ICANN-managed domain and doesn't fit the *specific `<= 3` rule*, only query `PublicSuffix(domain)`
   - Otherwise, query both
3. If the level of `PublicSuffix(domain)` is larger than 2, append `level=n-1` domain to the query list until it reaches `level=2`
   - Example: `PublicSuffix("abc.ipfs.dweb.link") = "ipfs.dweb.link"` which has level 3. Append `dweb.link` to query list
4. Query WHOIS servers in order and return **the longest domain** that can be found

**Specific `<= 3` rule**: All components in the public suffix have a length of 3 characters or fewer
- **Matches**: `co.uk`, `jpn.com`, `net.ua`
- **Does not match**: `github.io`, `zhitomir.ua`

> **Note**: All domains queried for WHOIS contain at least 2 levels.

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

> **Note**: PublicSuffix does not modify the case. We convert the result to lowercase and query for consistency, although domain names are not case-sensitive. The `query` field in `response` and `access log` preserves the original case.

## Prometheus Metrics
### HTTP Requests
* `whois_http_request_total{code=...}` (counter) - The number of requests per HTTP status code
* `whois_http_request_in_flight` (gauge) - Number of requests currently being served by the wrapped handler
* `whois_http_request_duration_seconds` (histogram) - Histogram of request latencies

### Service Metrics
#### Counters
* `whois_response_total{resp_by=...,resp_type=...,type=...}` (counter) - Number of responses by input type, component, and result type for queries
  * `resp_by` values:
    * `public_suffix`
    * `realtime`
    * `none`
  * `resp_type` values:
    * `found`
    * `not_found`
    * `error`
    * `timeout`
  * `type` values:
    * `domain`
    * `ip`
* `whois_nslookup_total{status=...}` (counter) - Number of responses by status when performing IP lookup for domains
  * `status` values:
    * `found`
    * `not_found`
    * `error`

## WHOIS Server Discovery
* **For domains**: WHOIS server information is fetched from [whois-server-xml](http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml)
* **For IP addresses**: Query `whois.arin.net` first to get the appropriate WHOIS server for the specific IP range
