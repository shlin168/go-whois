package domain

import (
	"testing"
)

func TestTKMLGQParser_TK(t *testing.T) {
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

	checkParserResult(t, "whois.dot.tk", "tk_ml_gq/case1.txt", "tk/ml/gq", exp)
}

func TestTKMLGQParser_ML(t *testing.T) {
	c := &Contact{
		Name:         "Mr DNS Admin",
		Email:        "google@domainthenet.net",
		Organization: "Google Inc",
		Country:      "U.S.A.",
		City:         "Mountain View",
		State:        "California",
		Street:       []string{"1600 Amphitheatre Parkway"},
		Postal:       "94043",
		Phone:        "+1-650-6234000",
		Fax:          "+1-650-6188571",
	}
	exp := &ParsedWhois{
		DomainName:     "GOOGLE.ML",
		NameServers:    []string{"ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"},
		CreatedDateRaw: "03/25/2013",
		CreatedDate:    "2013-03-25T00:00:00+00:00",
		ExpiredDateRaw: "06/25/2023",
		ExpiredDate:    "2023-06-25T00:00:00+00:00",
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech:       c,
			Billing:    c,
		},
	}

	checkParserResult(t, "whois.dot.ml", "tk_ml_gq/case2.txt", "tk/ml/gq", exp)
}
