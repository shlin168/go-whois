package domain

import (
	"testing"
)

func TestBRParser(t *testing.T) {
	// whois.nic.br
	exp := &ParsedWhois{
		DomainName: "unef.edu.br",
		NameServers: []string{
			"ns1.gruponobre.edu.br", "ns2.gruponobre.edu.br",
		},
		Statuses:       []string{"published"},
		CreatedDateRaw: "20040402 #1576459",
		CreatedDate:    "2004-04-02T00:00:00+00:00",
		UpdatedDateRaw: "20210811",
		UpdatedDate:    "2021-08-11T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: &Contact{
				Name: "Unidade de Ensino Superior de Feira de Santana S/C",
			},
		},
	}

	checkParserResult(t, "whois.nic.br", "br/case1.txt", "br", exp)
}
