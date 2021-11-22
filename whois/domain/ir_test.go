package domain

import (
	"testing"
)

func TestIRParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "google.ir",
		NameServers: []string{"ns1.googledomains.com", "ns2.googledomains.com",
			"ns3.googledomains.com", "ns4.googledomains.com"},
		UpdatedDateRaw: "2020-11-23",
		UpdatedDate:    "2020-11-23T00:00:00+00:00",
		ExpiredDateRaw: "2021-12-22",
		ExpiredDate:    "2021-12-22T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: &Contact{
				ID:           "go438-irnic",
				Email:        "hostmaster@ouriran.com",
				Organization: "Ravand Tazeh (ouriran)",
				Street: []string{
					"1600 Amphitheatre Parkway, Mountain View, CA, US",
					"level 2, 222-225 Beach Road, Mordialloc, Vic, AU",
				},
				Phone: "+61 3 9783 1800",
				Fax:   "+61 3 9783 6844",
			},
			Admin: &Contact{
				ID:           "in103-irnic",
				Email:        "hostmaster@ouriran.com",
				Organization: "Ravand Tazeh (ouriran)",
				Street:       []string{"level 2, 222-225 Beach Road, Mordialloc, Vic, AU"},
				Phone:        "+61 3 9783 1800",
				Fax:          "+61 3 9783 6844",
			},
			Tech: &Contact{
				ID:           "in103-irnic",
				Email:        "hostmaster@ouriran.com",
				Organization: "Ravand Tazeh (ouriran)",
				Street:       []string{"level 2, 222-225 Beach Road, Mordialloc, Vic, AU"},
				Phone:        "+61 3 9783 1800",
				Fax:          "+61 3 9783 6844",
			},
			Billing: &Contact{
				ID:           "ra50-irnic",
				Email:        "hostmaster@ouriran.com",
				Organization: "Ravand Tazeh (ouriran)",
			},
		},
	}

	checkParserResult(t, "whois.nic.ir", "ir/case1.txt", "ir", exp)

	c := &Contact{
		ID:           "no297-irnic",
		Email:        "esmailian@hostiran.com",
		Organization: "Noavaran Shabake Sabz Mehregan (HostIran Networks)",
		Street:       []string{"No. 13, Peymani Alley, Miremad St, Motahari St., Tehran, Tehran, IR"},
		Phone:        "+982128310",
		Fax:          "+982128310",
	}

	exp = &ParsedWhois{
		DomainName:     "htest.ir",
		NameServers:    []string{"ns1.hostiran.net", "ns2.hostiran.net"},
		UpdatedDateRaw: "2020-12-23",
		UpdatedDate:    "2020-12-23T00:00:00+00:00",
		ExpiredDateRaw: "2026-01-03",
		ExpiredDate:    "2026-01-03T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
		},
	}

	checkParserResult(t, "whois.nic.ir", "ir/case2.txt", "ir", exp)
}
