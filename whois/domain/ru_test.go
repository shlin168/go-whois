package domain

import (
	"testing"
)

func TestRUParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "GOOGLE.RU",
		Registrar: &Registrar{
			Name: "RU-CENTER-RU",
			URL:  "https://www.nic.ru/whois",
		},
		NameServers:    []string{"ns1.google.com.", "ns2.google.com.", "ns3.google.com.", "ns4.google.com."},
		CreatedDateRaw: "2004-03-03T21:00:00Z",
		CreatedDate:    "2004-03-03T21:00:00+00:00",
		ExpiredDateRaw: "2022-03-04T21:00:00Z",
		ExpiredDate:    "2022-03-04T21:00:00+00:00",
		Statuses:       []string{"DELEGATED", "REGISTERED", "VERIFIED"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Organization: "Google LLC",
			},
		},
	}

	checkParserResult(t, "whois.ripn.net", "ru/case1.txt", "ru", exp)
}
