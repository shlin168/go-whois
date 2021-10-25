package domain

import (
	"testing"
)

func TestSKParser(t *testing.T) {
	ra := &Contact{
		Name:         "Amazon Europe Core S.a.r.l.",
		Email:        "hostmaster@amazon.com",
		Organization: "Amazon Europe Core S.a.r.l.",
		Country:      "LU",
		City:         "Luxembourg",
		Street:       []string{"38 avenue John F. Kennedy"},
		Phone:        "+352.265240000",
	}
	tech := &Contact{
		Name:         "Technical Manager",
		Email:        "hostmaster@comlaude.com",
		Organization: "Com Laude",
		Country:      "UK",
		City:         "London",
		Street:       []string{"28-30 Little Russell Street"},
		State:        "London",
		Phone:        "+44.2074218250",
	}
	exp := &ParsedWhois{
		DomainName: "amazon.sk",
		Registrar: &Registrar{
			Name:              "Lorna J. Gradden",
			AbuseContactEmail: "hostmaster@comlaude.com",
			AbuseContactPhone: "+44.2074218250",
		},
		NameServers:    []string{"nsgbr.comlaude.co.uk", "nssui.comlaude.ch", "nsusa.comlaude.net"},
		CreatedDateRaw: "2003-11-12",
		CreatedDate:    "2003-11-12T00:00:00+00:00",
		UpdatedDateRaw: "2020-11-07",
		UpdatedDate:    "2020-11-07T00:00:00+00:00",
		ExpiredDateRaw: "2021-11-12",
		ExpiredDate:    "2021-11-12T00:00:00+00:00",
		Statuses:       []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"},
		Contacts: &Contacts{
			Registrant: ra,
			Admin:      ra,
			Tech:       tech,
		},
	}

	checkParserResult(t, "amazon.sk", "sk/case1.txt", "sk", exp)
}
