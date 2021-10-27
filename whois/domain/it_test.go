package domain

import (
	"testing"
)

func TestITParser(t *testing.T) {
	// whois.nic.it
	exp := &ParsedWhois{
		DomainName: "amazon.it",
		Registrar: &Registrar{
			Name: "ANCHOVY-REG",
		},
		NameServers: []string{
			"pdns1.ultradns.net", "pdns3.ultradns.org", "pdns4.ultradns.org", "pdns5.ultradns.info",
			"ns1.p31.dynect.net", "ns2.p31.dynect.net",
		},
		Statuses:       []string{"ok"},
		CreatedDateRaw: "2000-02-10 00:00:00",
		CreatedDate:    "2000-02-10T00:00:00+00:00",
		UpdatedDateRaw: "2021-01-28 00:51:03",
		UpdatedDate:    "2021-01-28T00:51:03+00:00",
		ExpiredDateRaw: "2022-01-12",
		ExpiredDate:    "2022-01-12T00:00:00+00:00",
		Dnssec:         "no",
		Contacts: &Contacts{
			Registrant: &Contact{
				Organization: "Amazon Europe Core S.à.r.l.",
				Street:       []string{"38 avenue John F. Kennedy", "Luxembourg City", "L-1855", "N.D.", "LU"},
			},
			Admin: &Contact{
				Name:         "Scott Hayden",
				Organization: "Amazon Europe Core S.à.r.l.",
				Street:       []string{"38 avenue John F. Kennedy", "Luxembourg City", "L-1855", "N.D.", "LU"},
			},
			Tech: &Contact{
				Name:         "Amazon Hostmaster",
				Organization: "Amazon.com, Inc.",
				Street:       []string{"PO BOX 81226", "Seattle", "98108-1300", "WA", "US"},
			},
		},
	}

	checkParserResult(t, "whois.nic.it", "it/case1.txt", "it", exp)
}
