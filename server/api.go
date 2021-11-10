package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/shlin168/go-whois/whois"
	wd "github.com/shlin168/go-whois/whois/domain"
	wip "github.com/shlin168/go-whois/whois/ip"
	"github.com/shlin168/go-whois/whois/utils"
)

/*
*    API Handlers:
        (1) Validate input
        (2) perform async WHOIS query and return the result
        (3) query for IP if query string contains ip=1
        (4) defer: write access log, increase corresponding metrics
*/

const (
	// Access Log
	name = "whois"

	// Access Log Fields
	accPath   = "path"
	accInput  = "input"
	accType   = "type"
	accErr    = "err"
	accRespBy = "resp_by"
	accNSErr  = "ns_err"

	// Values of RespBy
	respByRT   = "realtime"
	respByPS   = "public_suffix"
	respByNone = "none"
)

// WhoisReq represents whois requests from user
type WhoisReq struct {
	Query       string `json:"query"`
	IP          bool   `json:"ip"`
	WhoisServer string `json:"whois_server"`
}

// WhoisResp represent whois response format
type WhoisResp struct {
	Whois *wd.Whois `json:"whois"`
	Type  string    `json:"type"`
	Notes struct {
		OriginalQuery string   `json:"query"`
		PublicSuffixs []string `json:"public_suffixs,omitempty"`
		Error         string   `json:"error,omitempty"`
	} `json:"notes"`
	IP          []IP   `json:"ip,omitempty"`
	QueriedDate string `json:"queried_date"`
}

// WhoisIPResp represent whois response format for ip
type WhoisIPResp struct {
	Whois *wip.Whois `json:"whois"`
	Type  string     `json:"type"`
	Notes struct {
		OriginalQuery string `json:"query"`
		Error         string `json:"error,omitempty"`
	} `json:"notes"`
	QueriedDate string `json:"queried_date"`
}

// WhoisHandler handles POST requests to 'apiWhoisPath'
func WhoisHandler(cli *whois.Client, resolver *Resolver, acsLogger logrus.FieldLogger) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		var wr WhoisReq
		if err := decoder.Decode(&wr); err != nil {
			errMsg := fmt.Errorf("Payload decode error: %v", err)
			http.Error(resp, errMsg.Error(), http.StatusBadRequest)
			return
		}
		if len(wr.Query) == 0 {
			http.Error(resp, "Json payload should include 'query'", http.StatusBadRequest)
			return
		}
		var qType string
		var nsErr error
		respBy := respByNone
		status := whois.NewAsyncStatus(wr.WhoisServer)

		// write access log, increase metrics before leaving
		logFields := logrus.Fields{accPath: req.URL.Path, accInput: wr.Query}
		defer func(lf *logrus.Fields) {
			logFields[accType] = qType
			logFields[accRespBy] = respBy
			if status.Err != nil {
				logFields[accErr] = status.Err
			}
			IncrRespMetrics(qType, respBy, status.RespType)
			if qType == whois.TypeDomain && nsErr != nil {
				logFields[accNSErr] = nsErr
			}
			acsLogger.WithFields(*lf).Info(name)
		}(&logFields)

		// perform query - IP
		if utils.IsIP(wr.Query) {
			qType = whois.TypeIP
			status.DomainOrIP = wr.Query
			result := cli.QueryIPAsync(status)
			asyncResp := <-result
			respBy = respByRT
			if status.Err != nil {
				switch status.RespType {
				case whois.RespTypeTimeout:
					http.Error(resp, status.Err.Error(), http.StatusRequestTimeout)
					return
				case whois.RespTypeError:
					http.Error(resp, status.Err.Error(), http.StatusInternalServerError)
					return
				}
			}
			wResp := &WhoisIPResp{Whois: asyncResp}
			wResp.Type = qType
			wResp.Notes.OriginalQuery = wr.Query
			wResp.QueriedDate = utils.UTCNow().Format(wd.WhoisTimeFmt)
			resp.Header().Set("Content-Type", "application/json")
			if status.RespType == whois.RespTypeNotFound {
				resp.WriteHeader(http.StatusNotFound)
				json.NewEncoder(resp).Encode(wResp)
				return
			}
			if status.RespType == whois.RespTypeParseError {
				wResp.Notes.Error = status.Err.Error()
			}
			resp.WriteHeader(http.StatusOK)
			json.NewEncoder(resp).Encode(wResp)
			return
		}
		// perform query - domain, validate and trim port if given
		qType = whois.TypeDomain
		domain, err := utils.GetHost(wr.Query)
		if err != nil {
			status.RespType, status.Err = whois.RespTypeError, err
			http.Error(resp, "invalid input", http.StatusBadRequest)
			return
		}
		pslist, err := utils.GetPublicSuffixs(domain)
		if err != nil && len(pslist) == 0 {
			respBy = respByPS
			status.RespType, status.Err = whois.RespTypeError, err
			http.Error(resp, err.Error(), http.StatusBadRequest)
			return
		}
		status.PublicSuffixs = pslist
		result := cli.QueryPublicSuffixsAsync(status)
		asyncResp := <-result
		respBy = respByRT
		if status.Err != nil {
			switch status.RespType {
			case whois.RespTypeTimeout:
				http.Error(resp, status.Err.Error(), http.StatusRequestTimeout)
				return
			case whois.RespTypeError:
				http.Error(resp, status.Err.Error(), http.StatusInternalServerError)
				return
			}
		}
		wResp := &WhoisResp{Whois: asyncResp}
		wResp.Type = qType
		wResp.Notes.OriginalQuery = wr.Query
		wResp.Notes.PublicSuffixs = pslist
		wResp.QueriedDate = utils.UTCNow().Format(wd.WhoisTimeFmt)
		if status.RespType == whois.RespTypeNotFound {
			resp.Header().Set("Content-Type", "application/json")
			resp.WriteHeader(http.StatusNotFound)
			json.NewEncoder(resp).Encode(wResp)
			return
		}
		// nslookup
		if wr.IP {
			if wResp.IP, nsErr = resolver.Lookup(req.Context(), domain, wd.WhoisTimeFmt); nsErr != nil {
				if dnsErr, ok := nsErr.(*net.DNSError); ok && dnsErr.IsNotFound {
					IncrIPLookupMetrics(ipLookupNotFound)
				} else {
					IncrIPLookupMetrics(ipLookupError)
				}
			} else {
				IncrIPLookupMetrics(ipLookupFound)
			}
		}
		if status.RespType == whois.RespTypeParseError {
			wResp.Notes.Error = status.Err.Error()
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.WriteHeader(http.StatusOK)
		json.NewEncoder(resp).Encode(wResp)
		return
	}
}
