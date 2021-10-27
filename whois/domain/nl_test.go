package domain

import (
	"testing"
)

func TestNLParser(t *testing.T) {
	// whois.domain-registry.nl
	exp := &ParsedWhois{
		DomainName: "ergodirect.nl",
		Registrar: &Registrar{
			Name:              "team.blue nl B.V.",
			AbuseContactEmail: "abuse@nl.team.blue",
		},
		NameServers: []string{
			"ns0.transip.net", "ns1.transip.nl", "ns2.transip.eu",
		},
		Statuses:       []string{"active"},
		CreatedDateRaw: "2000-04-12",
		CreatedDate:    "2000-04-12T00:00:00+00:00",
		UpdatedDateRaw: "2021-05-01",
		UpdatedDate:    "2021-05-01T00:00:00+00:00",
		Dnssec:         "yes",
	}

	checkParserResult(t, "whois.domain-registry.nl", "nl/case1.txt", "nl", exp)

	exp = &ParsedWhois{
		DomainName: "t-mobile.nl",
		Registrar: &Registrar{
			Name:              "Deutsche Telekom AG",
			AbuseContactEmail: "sece.leitstellenservice@telekom.de",
			AbuseContactPhone: "+49.1805212095",
		},
		NameServers: []string{
			"ns-1395.awsdns-46.org", "ns-1880.awsdns-43.co.uk", "ns-201.awsdns-25.com", "ns-837.awsdns-40.net",
		},
		Statuses:       []string{"active"},
		CreatedDateRaw: "2000-05-21",
		CreatedDate:    "2000-05-21T00:00:00+00:00",
		UpdatedDateRaw: "2021-06-24",
		UpdatedDate:    "2021-06-24T00:00:00+00:00",
		Dnssec:         "yes",
	}

	checkParserResult(t, "whois.domain-registry.nl", "nl/case2.txt", "nl", exp)
}
