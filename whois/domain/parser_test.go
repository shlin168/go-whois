package domain

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-whois/whois/domain/testdata"
	"github.com/shlin168/go-whois/whois/utils"
)

func TestDefaultParser(t *testing.T) {
	c := &Contact{
		Organization: "GitHub, Inc.",
		State:        "CA",
		Country:      "US",
		Email:        "Select Request Email Form at https://domains.markmonitor.com/whois/github.io",
	}
	exp := &ParsedWhois{
		DomainName: "github.io",
		Registrar: &Registrar{
			IanaID:            "292",
			Name:              "MarkMonitor, Inc.",
			AbuseContactEmail: "abusecomplaints@markmonitor.com",
			AbuseContactPhone: "+1.2083895740",
			WhoisServer:       "whois.markmonitor.com",
			URL:               "www.markmonitor.com",
		},
		NameServers: []string{
			"dns1.p05.nsone.net", "dns2.p05.nsone.net", "dns3.p05.nsone.net", "ns-1622.awsdns-10.co.uk", "ns-692.awsdns-22.net",
		},
		CreatedDateRaw: "2013-03-08T11:41:10-0800",
		CreatedDate:    "2013-03-08T19:41:10+00:00",
		UpdatedDateRaw: "2021-02-04T02:17:45-0800",
		UpdatedDate:    "2021-02-04T10:17:45+00:00",
		ExpiredDateRaw: "2023-03-08T00:00:00-0800",
		ExpiredDate:    "2023-03-08T08:00:00+00:00",
		Statuses:       []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"},
		Dnssec:         "unsigned",
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
		},
	}

	parser := NewTLDDomainParser(utils.GetTLD("github.io"))
	assert.Equal(t, "default", parser.GetName())

	b, err := testdata.ReadRawtext("default/case1.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.GetParsedWhois(string(b))
	assert.Nil(t, err)
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestFoundByKey(t *testing.T) {
	rawtext := `
	ABC: 123
	Target: value
	`
	assert.Equal(t, "value", FoundByKey("Target", rawtext))
}

func TestWhoisNotFound(t *testing.T) {
	assert.True(t, WhoisNotFound("No data found"))
	assert.False(t, WhoisNotFound("found"))
}
