package domain

import (
	"testing"
)

func TestCZParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "megasklad.cz",
		Registrar: &Registrar{
			Name: "REG-GRANSY",
		},
		CreatedDate:    "2015-02-16T11:59:08+00:00",
		CreatedDateRaw: "16.02.2015 11:59:08",
		UpdatedDate:    "2018-09-07T12:04:05+00:00",
		UpdatedDateRaw: "07.09.2018 12:04:05",
		ExpiredDate:    "2022-02-16T00:00:00+00:00",
		ExpiredDateRaw: "16.02.2022",
		NameServers:    []string{"ns1.savana.cz", "ns2.savana.cz", "ns3.savana.cz"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:         "Filip Meister",
				Organization: "Datalogistic, s.r.o.",
				Street:       []string{"Slavojova 579/9", "Praha", "12800", "CZ"},
			},
			Tech: &Contact{
				Name:         "Pavel Höfner",
				Organization: "savana.cz s.r.o.",
				Street:       []string{"Lounská 983/43", "Děčín", "40502", "CZ"},
			},
		},
	}

	checkParserResult(t, "whois.nic.cz", "cz/case1.txt", "cz", exp)

	exp = &ParsedWhois{
		DomainName: "nyx.cz",
		Registrar: &Registrar{
			Name: "Lucie Vojtíková",
		},
		CreatedDate:    "2000-12-15T23:21:00+00:00",
		CreatedDateRaw: "15.12.2000 23:21:00",
		UpdatedDate:    "2021-06-15T20:41:04+00:00",
		UpdatedDateRaw: "15.06.2021 20:41:04",
		ExpiredDate:    "2025-12-17T00:00:00+00:00",
		ExpiredDateRaw: "17.12.2025",
		NameServers:    []string{"ns1.ignum.com", "ns2.ignum.cz"},
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:   "Marek Janda",
				Street: []string{"Bozeticka 3396/8", "Praha 4 - Modrany", "143 00", "CZ"},
			},
			Tech: &Contact{
				Organization: "Webglobe, s.r.o.",
				Street:       []string{"Vinohradská 190", "Praha 3", "130 61", "CZ"},
			},
		},
	}

	checkParserResult(t, "whois.nic.cz", "cz/case2.txt", "cz", exp)
}
