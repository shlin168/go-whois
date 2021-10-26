package domain

import (
	"testing"
)

func TestAMParserBlogSpot(t *testing.T) {
	at := &Contact{
		Name:    "Google LLC",
		Email:   "dns-admin@google.com",
		Country: "US",
	}
	registrant := &Contact{
		Name:    "Google LLC",
		Country: "US",
	}
	exp := &ParsedWhois{
		DomainName: "blogspot.am",
		Registrar: &Registrar{
			Name: "abcdomain (ABCDomain LLC)",
		},
		NameServers:    []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
		CreatedDateRaw: "2015-08-25",
		CreatedDate:    "2015-08-25T00:00:00+00:00",
		UpdatedDateRaw: "2021-08-06",
		UpdatedDate:    "2021-08-06T00:00:00+00:00",
		ExpiredDateRaw: "2022-08-25",
		ExpiredDate:    "2022-08-25T00:00:00+00:00",
		Statuses:       []string{"active", "registrar locked"},
		Contacts: &Contacts{
			Registrant: registrant,
			Admin:      at,
			Tech:       at,
		},
	}

	checkParserResult(t, "blogspot.am", "am/case1.txt", "am", exp)
}

func TestAMParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "amazon.am",
		Registrar: &Registrar{
			Name: "abcdomain (ABCDomain LLC)",
		},
		NameServers: []string{"ns1.p31.dynect.net", "ns2.p31.dynect.net", "ns3.p31.dynect.net",
			"pdns1.ultradns.net", "pdns2.ultradns.net", "pdns3.ultradns.org"},
		CreatedDateRaw: "1999-09-09",
		CreatedDate:    "1999-09-09T00:00:00+00:00",
		UpdatedDateRaw: "2021-03-12",
		UpdatedDate:    "2021-03-12T00:00:00+00:00",
		ExpiredDateRaw: "2022-04-15",
		ExpiredDate:    "2022-04-15T00:00:00+00:00",
		Statuses:       []string{"active"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Domain Privacy",
				Email:   "privacy@internet.am",
				Country: "AM",
			},
		},
	}

	checkParserResult(t, "amazon.am", "am/case2.txt", "am", exp)
}
