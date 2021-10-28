package domain

import (
	"testing"
)

func TestBEParser(t *testing.T) {
	// whois.dns.be
	exp := &ParsedWhois{
		DomainName: "google.be",
		Registrar: &Registrar{
			Name: "MarkMonitor Inc.",
			URL:  "http://www.markmonitor.com",
		},
		NameServers: []string{
			"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com",
		},
		CreatedDateRaw: "Tue Dec 12 2000",
		CreatedDate:    "2000-12-12T00:00:00+00:00",
		Statuses:       []string{"NOT AVAILABLE", "clientTransferProhibited"},
	}

	checkParserResult(t, "whois.dns.be", "be/case1.txt", "be", exp)

	exp = &ParsedWhois{
		DomainName: "mezure.be",
		Registrar: &Registrar{
			Name: "Registrar.nl B.V.",
			URL:  "http://registrar.nl",
		},
		NameServers: []string{
			"ns.coredns.org", "ns1.server.eu", "ns2.server.eu",
		},
		CreatedDateRaw: "Fri Jan 22 2016",
		CreatedDate:    "2016-01-22T00:00:00+00:00",
		Statuses:       []string{"NOT AVAILABLE"},
	}

	checkParserResult(t, "whois.dns.be", "be/case2.txt", "be", exp)
}
