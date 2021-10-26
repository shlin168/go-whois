package domain

import (
	"testing"
)

func TestARParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "steamp.com.ar",
		Registrar: &Registrar{
			Name: "nicar",
		},
		NameServers:    []string{"ns3.hostmar.com", "ns4.hostmar.com"},
		CreatedDateRaw: "2020-04-30 23:05:51.098561",
		CreatedDate:    "2020-04-30T23:05:51+00:00",
		UpdatedDateRaw: "2021-06-09 15:27:12.357274",
		UpdatedDate:    "2021-06-09T15:27:12+00:00",
		ExpiredDateRaw: "2022-04-30 00:00:00",
		ExpiredDate:    "2022-04-30T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: &Contact{
				Name: "FERREYRA EVELYN AYELEN MAIVE",
			},
		},
	}

	checkParserResult(t, "steamp.com.ar", "ar/case1.txt", "ar", exp)
}
