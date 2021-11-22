package domain

import (
	"testing"
)

func TestATParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "reitpaedagogin.at",
		Registrar: &Registrar{
			Name: "Emerion WebHosting GmbH ( https://nic.at/registrar/13 )",
		},
		NameServers:    []string{"ns1.emerion.com", "ns2.emerion.com"},
		UpdatedDateRaw: "20160402 09:36:26",
		UpdatedDate:    "2016-04-02T09:36:26+00:00",
		Contacts: &Contacts{
			Tech: &Contact{
				Name:         "emerion Domain Admin",
				Email:        "domain-admin@emerion.com",
				Organization: "emerion WebHosting GmbH",
				Country:      "Austria",
				City:         "Wien",
				Street:       []string{"Hofmuehlgasse 3"},
				Postal:       "1060",
				Phone:        "+4312988800",
				Fax:          "+4318774888",
			},
		},
	}

	checkParserResult(t, "whois.nic.at", "at/case1.txt", "at", exp)

	c := &Contact{
		Email:        "dnsadmin@awsg.at",
		Organization: "Austria Wirtschaftsservice Gesellschaft m.b.H",
		Country:      "Austria",
		City:         "Wien",
		Street:       []string{"Walcherstrasse 11a"},
		Postal:       "1020",
		Phone:        "+43150175",
		Fax:          "+43150175900",
	}
	exp = &ParsedWhois{
		DomainName: "aws.at",
		Registrar: &Registrar{
			Name: "baddaboom IT Service GmbH ( https://nic.at/registrar/633 )",
		},
		NameServers:    []string{"ns1.awsg.at", "nsa.baddaboom.at", "nsb.baddaboom.at"},
		UpdatedDateRaw: "20150910 15:12:57",
		UpdatedDate:    "2015-09-10T15:12:57+00:00",
		Contacts: &Contacts{
			Registrant: c,
			Tech:       c,
		},
	}

	checkParserResult(t, "whois.nic.at", "at/case2.txt", "at", exp)
}
