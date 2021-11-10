package domain

import (
	"testing"
)

func TestEUParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "onlinecasinos24.eu",
		Registrar: &Registrar{
			Name: "Dynadot, LLC",
			URL:  "https://www.dynadot.com/domain/eu.html",
		},
		NameServers: []string{"ns1.onlinecasinos24.eu", "ns2.onlinecasinos24.eu"},
		Contacts: &Contacts{
			Tech: &Contact{
				Email:        "info@dynadot.com",
				Organization: "Dynadot LLC",
			},
		},
	}

	checkParserResult(t, "whois.eu", "eu/case1.txt", "eu", exp)
}
