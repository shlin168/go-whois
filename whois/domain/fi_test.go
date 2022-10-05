package domain

import (
	"testing"
)

func TestFIParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "zakony.fi",
		Registrar: &Registrar{
			Name: "Euronic Oy",
			URL:  "www.domainkeskus.com",
		},
		Statuses:       []string{"Registered"},
		NameServers:    []string{"ns1.euronic.fi", "ns2.euronic.fi", "ns3.euronic.fi"},
		CreatedDate:    "2015-09-16T16:16:22+00:00",
		CreatedDateRaw: "16.9.2015 16:16:22",
		UpdatedDate:    "2020-08-12T13:56:17+00:00",
		UpdatedDateRaw: "12.8.2020 13:56:17",
		ExpiredDate:    "2025-09-16T16:16:21+00:00",
		ExpiredDateRaw: "16.9.2025 16:16:21",
		Dnssec:         "no",
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Kulttuuri-Innovaatioden Kehitys KIK ry",
				Country: "Finland",
				City:    "Helsinki",
				Street:  []string{"Sahaajankatu 20 A"},
				Postal:  "00880",
			},
		},
	}

	checkParserResult(t, "whois.fi", "fi/case1.txt", "fi", exp)

	exp = &ParsedWhois{
		DomainName: "google.fi",
		Registrar: &Registrar{
			Name: "MarkMonitor Inc.",
			URL:  "www.markmonitor.com",
		},
		Statuses:       []string{"Registered"},
		NameServers:    []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
		CreatedDate:    "2006-06-30T00:00:00+00:00",
		CreatedDateRaw: "30.6.2006 00:00:00",
		UpdatedDate:    "2022-06-02T12:24:38+00:00",
		UpdatedDateRaw: "2.6.2022 12:24:38",
		ExpiredDate:    "2023-07-04T10:15:55+00:00",
		ExpiredDateRaw: "4.7.2023 10:15:55",
		Dnssec:         "no",
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:    "Google LLC",
				Country: "United States of America",
				City:    "Mountain View",
				Street:  []string{"1600 Amphitheatre Parkway"},
				Postal:  "94043",
			},
			Tech: &Contact{
				Name:  "Google LLC",
				Email: "ccops@markmonitor.com",
			},
		},
	}

	checkParserResult(t, "whois.fi", "fi/case2.txt", "fi", exp)
}
