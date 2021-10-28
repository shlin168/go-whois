package domain

import (
	"testing"
)

func TestPLParser(t *testing.T) {
	// whois.dns.pl
	exp := &ParsedWhois{
		DomainName: "amazon.pl",
		Registrar: &Registrar{
			Name:              "Com Laude t/a Com Laude",
			AbuseContactEmail: "admin@comlaude.com",
			AbuseContactPhone: "+44 20 7421 8250",
		},
		NameServers: []string{
			"ns1.p31.dynect.net.", "ns2.p31.dynect.net.", "ns3.p31.dynect.net.", "ns4.p31.dynect.net.",
			"pdns1.ultradns.net.", "pdns2.ultradns.net.", "pdns3.ultradns.org.", "pdns4.ultradns.org.", "pdns5.ultradns.info.",
		},
		CreatedDateRaw: "1998.10.06 13:00:00",
		CreatedDate:    "1998-10-06T13:00:00+00:00",
		UpdatedDateRaw: "2021.10.01 01:01:27",
		UpdatedDate:    "2021-10-01T01:01:27+00:00",
		ExpiredDateRaw: "2022.10.05 14:00:00",
		ExpiredDate:    "2022-10-05T14:00:00+00:00",
		Dnssec:         "Unsigned",
	}

	checkParserResult(t, "whois.dns.pl", "pl/case1.txt", "pl", exp)

	exp = &ParsedWhois{
		DomainName: "inpost.pl",
		Registrar: &Registrar{
			Name: "nazwa.pl sp. z o.o.",
		},
		NameServers: []string{
			"ns.easypack24.net.", "ns.inpost.pl.", "ns.integer.pl.", "ns.paczkomaty.pl.",
		},
		CreatedDateRaw: "2006.04.10 12:46:55",
		CreatedDate:    "2006-04-10T12:46:55+00:00",
		UpdatedDateRaw: "2021.04.09 16:10:50",
		UpdatedDate:    "2021-04-09T16:10:50+00:00",
		ExpiredDateRaw: "2022.04.10 12:46:55",
		ExpiredDate:    "2022-04-10T12:46:55+00:00",
		Dnssec:         "Unsigned",
	}

	checkParserResult(t, "whois.dns.pl", "pl/case2.txt", "pl", exp)
}
