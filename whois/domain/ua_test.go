package domain

import (
	"testing"
)

func TestUAParser(t *testing.T) {
	c := &Contact{
		Name:         "n/a",
		Email:        "not published",
		Organization: "not published",
		Street:       []string{"n/a"},
		Phone:        "not published",
		Fax:          "not published",
	}
	exp := &ParsedWhois{
		DomainName: "dobrodoc.ua",
		Registrar: &Registrar{
			Name:              "ua.nic",
			AbuseContactEmail: "abuse@nic.ua",
			AbuseContactPhone: "+380445933222",
			URL:               "http://nic.ua",
		},
		NameServers:    []string{"alex.ns.cloudflare.com", "pola.ns.cloudflare.com"},
		CreatedDateRaw: "2018-02-01 15:53:47+02",
		CreatedDate:    "2018-02-01T13:53:47+00:00",
		UpdatedDateRaw: "2021-09-09 22:15:24+03",
		UpdatedDate:    "2021-09-09T19:15:24+00:00",
		ExpiredDateRaw: "2022-02-01 15:53:47+02",
		ExpiredDate:    "2022-02-01T13:53:47+00:00",
		Statuses:       []string{"linked", "ok"},
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
		},
	}

	checkParserResult(t, "whois.ua", "ua/case1.txt", "ua", exp)
}
