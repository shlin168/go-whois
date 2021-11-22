package domain

import (
	"testing"
)

func TestTWParser(t *testing.T) {
	c := &Contact{
		Name:  "Rochefort Denis",
		Email: "dzwalker@protonmail.com",
	}
	exp := &ParsedWhois{
		DomainName:  "youngtube.tw",
		NameServers: []string{"keenan.ns.cloudflare.com", "maisie.ns.cloudflare.com"},
		Registrar: &Registrar{
			Name: "101 Domain Inc.",
			URL:  "http://www.101domain.com/",
		},
		CreatedDateRaw: "2021-04-19 10:54:59 (UTC+8)",
		CreatedDate:    "2021-04-19T02:54:59+00:00",
		ExpiredDateRaw: "2022-04-19 10:54:59 (UTC+8)",
		ExpiredDate:    "2022-04-19T02:54:59+00:00",
		Statuses:       []string{"clientTransferProhibited"},
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
		},
	}

	checkParserResult(t, "whois.twnic.net.tw", "tw/case1.txt", "tw", exp)

	c = &Contact{
		Name:  "Han Yuan \\u5f35",
		Email: "hanyuan109@gmail.com",
	}
	exp = &ParsedWhois{
		DomainName:  "taiwanlands.com.tw",
		NameServers: []string{"ns47.cx901.com", "ns48.cx901.com"},
		Registrar: &Registrar{
			Name: "GoDaddy",
			URL:  "http://www.GoDaddy.com/",
		},
		CreatedDateRaw: "2021-06-25 00:25:53 (UTC+8)",
		CreatedDate:    "2021-06-24T16:25:53+00:00",
		ExpiredDateRaw: "2022-06-25 00:25:53 (UTC+8)",
		ExpiredDate:    "2022-06-24T16:25:53+00:00",
		Statuses:       []string{"clientDeleteProhibited", "clientRenewProhibited", "clientTransferProhibited", "clientUpdateProhibited"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Han Yuan \\u5f35",
				Email:   "hanyuan109@gmail.com",
				Country: "TW",
			},
			Admin: c,
			Tech:  c,
		},
	}

	checkParserResult(t, "whois.twnic.net", "tw/case2.txt", "tw", exp)
}
