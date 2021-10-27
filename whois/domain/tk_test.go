package domain

import (
	"testing"
)

func TestTKParser(t *testing.T) {
	rat := &Contact{
		Name:         "Hostmaster Amazon Legal Dept.",
		Email:        "hostmaster@amazon.com",
		Organization: "Amazon Technologies, Inc.",
		Country:      "U.S.A.",
		City:         "Reno",
		State:        "Nevada",
		Street:       []string{"P.O. Box 8102"},
		Postal:       "89507",
		Phone:        "+1-2062664064",
		Fax:          "+1-2062667010",
	}
	b := &Contact{
		Name:         "Domain Administrator",
		Email:        "ccopsbilling@markmonitor.com",
		Organization: "MarkMonitor Inc.",
		Country:      "U.S.A.",
		City:         "Meridian",
		State:        "Idaho",
		Street:       []string{"3540 E Longwing Lane Suite 300"},
		Postal:       "83646",
		Phone:        "+1-2083895740",
		Fax:          "+1-2083895771",
	}
	exp := &ParsedWhois{
		DomainName: "AMAZON.TK",
		NameServers: []string{
			"NS2.P31.DYNECT.NET", "PDNS1.ULTRADNS.NET", "PDNS2.ULTRADNS.NET",
			"PDNS5.ULTRADNS.INFO", "PDNS6.ULTRADNS.CO.UK"},
		CreatedDateRaw: "09/17/2014",
		CreatedDate:    "2014-09-17T00:00:00+00:00",
		ExpiredDateRaw: "12/11/2021",
		ExpiredDate:    "2021-12-11T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: rat,
			Admin:      rat,
			Tech:       rat,
			Billing:    b,
		},
	}

	checkParserResult(t, "whois.dot.tk", "tk/case1.txt", "tk", exp)
}
