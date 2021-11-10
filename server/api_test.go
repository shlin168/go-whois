package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-whois/whois"
)

const testTimeout = 1 * time.Second

func expectedWhoisAPIMetrics(m prometheus.Collector, expVal int, labels ...string) error {
	defer m.(*prometheus.CounterVec).Reset()
	metadata := `
	# HELP whois_response_total The amount of response from per input_type, per components and per result type for queries
	# TYPE whois_response_total counter
	`
	if len(labels) != 3 {
		return errors.New("should input 3 labels: 'resp_type', 'resp_by' and 'type' for metrics")
	}
	expected := fmt.Sprintf(`
	whois_response_total{resp_by="%s",resp_type="%s",type="%s"} %d
	`, labels[0], labels[1], labels[2], expVal)
	return testutil.CollectAndCompare(m, strings.NewReader(metadata+expected))
}

func TestWhoisHandler(t *testing.T) {
	// mock whois server
	logger := logrus.StandardLogger()
	whoisServer, err := whois.StartMockWhoisServer(":0")
	require.Nil(t, err)
	defer whoisServer.Close()
	whoisServerAddr := whoisServer.Addr().String()
	whoisServerHost := whoisServerAddr[:strings.LastIndex(whoisServerAddr, ":")]
	testWhoisPort, err := strconv.Atoi(whoisServerAddr[strings.LastIndex(whoisServerAddr, ":")+1:])
	require.Nil(t, err)
	testServerMap := whois.DomainWhoisServerMap{
		"io":  []whois.WhoisServer{{Host: whoisServerHost}},
		"app": []whois.WhoisServer{{Host: whoisServerHost}},
		"aaa": []whois.WhoisServer{{Host: whoisServerHost}},
	}
	client, err := whois.NewClient(
		whois.WithTimeout(testTimeout),
		whois.WithServerMap(testServerMap),
		whois.WithTestingWhoisPort(testWhoisPort),
		whois.WithErrLogger(logger),
	)
	require.Nil(t, err)

	// expected domain found result
	expParsedWhois, err := client.Parse(whois.TestDomain, whois.NewRaw(whois.TestDomainWhoisRawText, whoisServerHost))
	require.Nil(t, err)
	expResp := &WhoisResp{
		Whois: expParsedWhois,
		Type:  whois.TypeDomain,
	}
	expResp.Notes.OriginalQuery = whois.TestDomain
	expResp.Notes.PublicSuffixs = []string{"github.io"}

	// expected IP found result
	expParsedWhoisIP, err := client.ParseIP(whois.TestIP, whois.NewRaw(whois.TestIPWhoisRawText, whoisServerHost))
	require.Nil(t, err)
	expIPResp := &WhoisIPResp{
		Whois: expParsedWhoisIP,
		Type:  whois.TypeIP,
	}

	// set metrics
	MetricRegister(prometheus.DefaultRegisterer)

	runWhoisHandler := func(t *testing.T, domainOrIp string, expCode int, whoisServer ...string) string {
		reqBody := &WhoisReq{Query: domainOrIp}
		if len(whoisServer) > 0 {
			reqBody.WhoisServer = whoisServer[0]
		}
		reqBodyContent, err := json.Marshal(reqBody)
		require.Nil(t, err)
		request, _ := http.NewRequest(http.MethodPost, apiWhoisPath, bytes.NewReader(reqBodyContent))
		response := httptest.NewRecorder()
		wHandler := WhoisHandler(client, nil, logger)
		wHandler(response, request)
		if expCode == http.StatusInternalServerError && response.Code == http.StatusRequestTimeout {
			// sometimes it get 408 while expecting 500, log it without raising error
			return "unexpected_timeout"
		}
		require.Equal(t, expCode, response.Code)
		if expCode != http.StatusOK && expCode != http.StatusNotFound {
			return ""
		}
		body, err := ioutil.ReadAll(response.Body)
		return string(body)
	}

	conv2DomainResult := func(content string) *WhoisResp {
		var wResp WhoisResp
		require.Nil(t, json.NewDecoder(strings.NewReader(content)).Decode(&wResp))
		return &wResp
	}

	conv2IPResult := func(content string) *WhoisIPResp {
		var wResp WhoisIPResp
		require.Nil(t, json.NewDecoder(strings.NewReader(content)).Decode(&wResp))
		return &wResp
	}

	cmpMarshalResp := func(exp, target *WhoisResp) {
		expOut, err := json.Marshal(exp)
		require.Nil(t, err)
		targetOut, err := json.Marshal(target)
		require.Nil(t, err)
		assert.Empty(t, cmp.Diff(string(expOut), string(targetOut)))
	}

	cmpMarshalIPResp := func(exp, target *WhoisIPResp) {
		expOut, err := json.Marshal(exp)
		require.Nil(t, err)
		targetOut, err := json.Marshal(target)
		require.Nil(t, err)
		assert.Empty(t, cmp.Diff(string(expOut), string(targetOut)))
	}

	t.Run("200_Found", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestDomain, http.StatusOK)
		wResp := conv2DomainResult(respBody)
		expResp.QueriedDate = wResp.QueriedDate
		cmpMarshalResp(expResp, wResp)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="found", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeFound, whois.TypeDomain))
	})

	t.Run("200_Found_with_port", func(t *testing.T) {
		testDomainWithPort := whois.TestDomain + ":80" // github.io:80
		respBody := runWhoisHandler(t, testDomainWithPort, http.StatusOK)
		wResp := conv2DomainResult(respBody)
		expResp.QueriedDate = wResp.QueriedDate
		expResp.Notes.OriginalQuery = testDomainWithPort
		cmpMarshalResp(expResp, wResp)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="found", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeFound, whois.TypeDomain))
	})

	t.Run("200_Found_IP", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestIP, http.StatusOK, whoisServerHost) // specify whois server to avoid query ARIN
		wResp := conv2IPResult(respBody)
		expIPResp.Notes.OriginalQuery = whois.TestIP
		expIPResp.QueriedDate = wResp.QueriedDate
		cmpMarshalIPResp(expIPResp, wResp)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="found", type="ip")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeFound, whois.TypeIP))
	})

	t.Run("400_NonJson_req_format", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodPost, apiWhoisPath, strings.NewReader("wrong_format"))
		response := httptest.NewRecorder()
		wHandler := WhoisHandler(client, nil, logger)
		wHandler(response, request)
		assert.Equal(t, http.StatusBadRequest, response.Code)
		// not update metrics
	})

	t.Run("400_no_query", func(t *testing.T) {
		emptyDomain := ""
		respBody := runWhoisHandler(t, emptyDomain, http.StatusBadRequest)
		assert.Empty(t, respBody)
		// not update metrics
	})

	t.Run("400_Invalid_query", func(t *testing.T) {
		invalidDomain := "hello[abc].com:80"
		respBody := runWhoisHandler(t, invalidDomain, http.StatusBadRequest)
		assert.Empty(t, respBody)
		// Metrics: [add] whois_response_total(resp_by="none", resp_type="error", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByNone, whois.RespTypeError, whois.TypeDomain))
	})

	t.Run("400_PublicSuffix_error", func(t *testing.T) {
		invalidDomain := "com"
		respBody := runWhoisHandler(t, invalidDomain, http.StatusBadRequest)
		assert.Empty(t, respBody)
		// Metrics: [add] whois_response_total(resp_by="public_suffix", resp_type="error", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByPS, whois.RespTypeError, whois.TypeDomain))
	})

	t.Run("404_Not_Found", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestNotFoundDomain, http.StatusNotFound)
		wResp := conv2DomainResult(respBody)
		assert.Equal(t, whois.TestNotFoundDomain, wResp.Notes.OriginalQuery)
		assert.Equal(t, "No match for "+whois.TestNotFoundDomain, wResp.Whois.RawText)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="not_found", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeNotFound, whois.TypeDomain))
	})

	t.Run("404_Not_Found_IP", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestNotFoundIP, http.StatusNotFound, whoisServerHost) // specify whois server to avoid query ARIN
		wResp := conv2IPResult(respBody)
		assert.Equal(t, whois.TestNotFoundIP, wResp.Notes.OriginalQuery)
		assert.Equal(t, "No match found for "+whois.TestNotFoundIP, wResp.Whois.RawText)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="not_found", type="ip")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeNotFound, whois.TypeIP))
	})

	t.Run("408_timeout", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestTimeoutDomain, http.StatusRequestTimeout)
		assert.Empty(t, respBody)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="timeout", type="domain")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeTimeout, whois.TypeDomain))
	})

	t.Run("408_timeout", func(t *testing.T) {
		respBody := runWhoisHandler(t, whois.TestTimeoutIP, http.StatusRequestTimeout, whoisServerHost)
		assert.Empty(t, respBody)
		// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="timeout", type="ip")
		assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeTimeout, whois.TypeIP))
	})

	t.Run("500_unexpected_error", func(t *testing.T) {
		respBody := runWhoisHandler(t, "abc.abc", http.StatusInternalServerError) // unknown whois server
		if respBody == "unexpected_timeout" {
			t.Log("get timeout(408) while expecting internal error(500)")
			// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="timeout", type="domain")
			assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeTimeout, whois.TypeDomain))
		} else {
			assert.Empty(t, respBody)
			// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="error", type="domain")
			assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeError, whois.TypeDomain))
		}
	})

	t.Run("500_unexpected_error", func(t *testing.T) {
		respBody := runWhoisHandler(t, "103.42.34.68", http.StatusInternalServerError, "unknownwhoisserver") // unknown whois server
		if respBody == "unexpected_timeout" {
			t.Log("get timeout(408) while expecting internal error(500)")
			// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="timeout", type="ip")
			assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeTimeout, whois.TypeIP))
		} else {
			assert.Empty(t, respBody)
			// Metrics: [add] whois_response_total(resp_by="realtime", resp_type="error", type="ip")
			assert.Nil(t, expectedWhoisAPIMetrics(whoisAPIRespTotal, 1, respByRT, whois.RespTypeError, whois.TypeIP))
		}
	})

	// unset metrics
	MetricUnRegister(prometheus.DefaultRegisterer)
}
