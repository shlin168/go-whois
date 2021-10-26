package domain

import (
	"testing"
)

func TestASParser(t *testing.T) {
	// whois.nic.as
	exp := &ParsedWhois{
		DomainName: "nov.as",
		Registrar: &Registrar{
			Name: "101domain GRS Limited (http://www.101domain.com)",
		},
		NameServers:    []string{"ns1.101domain.com", "ns5.101domain.com"},
		CreatedDateRaw: "Registered on 08th November 2012 at 00:00:00.000",
		CreatedDate:    "2012-11-08T00:00:00+00:00",
		Statuses:       []string{"Active", "Transfer Prohibited by Registrar"},
	}

	checkParserResult(t, "nov.as", "as/case1.txt", "as", exp)
}
