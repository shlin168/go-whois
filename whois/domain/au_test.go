package domain

import (
	"testing"
)

func TestAUParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "PAKENHAMSC.VIC.EDU.AU",
		Registrar: &Registrar{
			Name:              "EDUCATION SERVICES AUSTRALIA LIMITED",
			AbuseContactEmail: "registrar@esa.edu.au",
			AbuseContactPhone: "+61.399109829",
			WhoisServer:       "https://whois.auda.org.au",
			URL:               "https://www.domainname.edu.au",
		},
		UpdatedDateRaw: "2021-10-31T19:59:23Z",
		UpdatedDate:    "2021-10-31T19:59:23+00:00",
		NameServers:    []string{"NS1.IINETHOSTING.NET.AU", "NS2.IINETHOSTING.NET.AU", "NS3.IINETHOSTING.NET.AU"},
		Statuses:       []string{"serverRenewProhibited"},
		Dnssec:         "unsigned",
		Contacts: &Contacts{
			Registrant: &Contact{
				Name:         "Alan Thwaites",
				Organization: "Alan Thwaites",
			},
			Tech: &Contact{
				Name: "Alan Thwaites",
			},
		},
	}

	checkParserResult(t, "whois.audns.net.au", "au/case1.txt", "au", exp)
}
