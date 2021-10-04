package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/shlin168/go-whois/whois"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	localAddr  = "localhost:20168"
	metricAddr = "localhost:20169"
)

// TestBaseConf is base config for testing if config is not given in tests
var TestBaseConf = &ServerCfg{
	ipLookupTimeout: DefaultIpLookupTimeout,
	whoisTimeout:    DefaultTimeout,
}

type TestWhoisServer struct {
	Server
}

func NewTestWhoisServer(conf *ServerCfg) (*TestWhoisServer, error) {
	if conf == nil {
		conf = TestBaseConf
	}
	acsLogger := logrus.New()
	acsLogger.SetOutput(os.Stdout)
	acsLogger.SetLevel(logrus.InfoLevel)
	errLogger := logrus.New()
	errLogger.SetOutput(os.Stdout)
	errLogger.SetLevel(logrus.InfoLevel)
	server, err := New(conf, errLogger, acsLogger)
	if err != nil {
		return nil, err
	}
	return &TestWhoisServer{*server}, nil
}

func getWhoiServerResp(t *testing.T, query string, whoisServer ...string) (code int, body []byte, err error) {
	reqBody := &WhoisReq{Query: query}
	if len(whoisServer) > 0 {
		reqBody.WhoisServer = whoisServer[0]
	}
	reqBodyContent, err := json.Marshal(reqBody)
	require.Nil(t, err)
	req, err := http.NewRequest(http.MethodPost, "http://"+localAddr+apiWhoisPath, bytes.NewReader(reqBodyContent))
	if err != nil {
		return 0, nil, fmt.Errorf("compose request error: %v", err)
	}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("send request error: %v", err)
	}
	content, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("read content error: %v", err)
	}
	return resp.StatusCode, content, nil
}

func TestServer(t *testing.T) {
	// initialize and start whois server
	ts, err := NewTestWhoisServer(TestBaseConf)
	ts.resolver = nil // not testing resolver
	require.Nil(t, err)
	ts.reg = prometheus.DefaultRegisterer
	go ts.Start(localAddr, metricAddr)
	time.Sleep(1 * time.Second) // wait for server to start

	// send 'github.io' and should return 200
	code, content, err := getWhoiServerResp(t, whois.TestDomain)
	assert.Equal(t, http.StatusOK, code)
	assert.NotEmpty(t, content)
	assert.Nil(t, err)

	// send 'not.found.ab38ffdefwfef.com' and should return 404
	code, content, err = getWhoiServerResp(t, "not.found.ab38ffdefwfef.com")
	assert.Equal(t, http.StatusNotFound, code)
	assert.NotEmpty(t, content)
	assert.Nil(t, err)

	// send 'unkonwnTLD.abcde' and should return 500 (unknown whois server)
	code, content, err = getWhoiServerResp(t, "unkonwnTLD.abcde")
	assert.Equal(t, http.StatusInternalServerError, code)
	assert.Equal(t, "unknown whois server\n", string(content))
	assert.Nil(t, err)

	ts.Close()
}
