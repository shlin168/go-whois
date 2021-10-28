package domain

import (
	"testing"
)

func TestFRParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "fantasktic.fr",
		Registrar: &Registrar{
			Name:              "OVH",
			AbuseContactEmail: "support@ovh.net",
			AbuseContactPhone: "+33 8 99 70 17 61",
			URL:               "http://www.ovh.com",
		},
		NameServers:    []string{"dns19.ovh.net", "ns19.ovh.net"},
		CreatedDateRaw: "2011-05-31T14:43:38Z",
		CreatedDate:    "2011-05-31T14:43:38+00:00",
		UpdatedDateRaw: "2021-07-31T20:19:12Z",
		UpdatedDate:    "2021-07-31T20:19:12+00:00",
		ExpiredDateRaw: "2022-05-31T14:43:38Z",
		ExpiredDate:    "2022-05-31T14:43:38+00:00",
		Statuses:       []string{"ACTIVE"},
		Contacts: &Contacts{
			Registrant: &Contact{
				ID:      "R2462-FRNIC",
				Name:    "Relatia",
				Email:   "nklain@relatia.fr",
				Country: "FR",
				Street:  []string{"Relatia", "31, rue du 4 Septembre", "75002 PARIS"},
				Phone:   "+33.144568725",
			},
			Admin: &Contact{
				ID:      "R49857-FRNIC",
				Name:    "Relatia",
				Email:   "ssck1775j74qdhpdencn@k.o-w-o.info",
				Country: "FR",
				Street:  []string{"Relatia", "8, rue de choiseul", "75002 PARIS"},
				Phone:   "+33.144500532",
			},
			Tech: &Contact{
				ID:      "OVH5-FRNIC",
				Name:    "OVH NET",
				Email:   "tech@ovh.net",
				Country: "FR",
				Street:  []string{"OVH", "140, quai du Sartel", "59100 Roubaix"},
				Phone:   "+33 8 99 70 17 61",
			},
		},
	}

	checkParserResult(t, "whois.nic.fr", "fr/case1.txt", "fr", exp)

	c := &Contact{
		ID:      "XP2148-FRNIC",
		Name:    "X-PRIME",
		Email:   "4b1ca811c7b65d6705314d8fc7e4bd4e-31639884@contact.gandi.net",
		Country: "FR",
		Street:  []string{"X-PRIME", "10 rue des trente six ponts", "31400 TOULOUSE"},
		Phone:   "+33.534449678",
	}
	exp = &ParsedWhois{
		DomainName: "roku-gin.fr",
		Registrar: &Registrar{
			Name:              "GANDI",
			AbuseContactEmail: "support@support.gandi.net",
			AbuseContactPhone: "+33 1 70 37 76 61",
			URL:               "https://www.gandi.net/fr/tlds/fr/",
		},
		NameServers:    []string{"ns-216-b.gandi.net", "ns-245-a.gandi.net", "ns-49-c.gandi.net"},
		CreatedDateRaw: "2021-10-22T07:52:30Z",
		CreatedDate:    "2021-10-22T07:52:30+00:00",
		ExpiredDateRaw: "2022-10-22T07:52:30Z",
		ExpiredDate:    "2022-10-22T07:52:30+00:00",
		Statuses:       []string{"ACTIVE"},
		Contacts: &Contacts{
			Registrant: c,
			Admin:      c,
			Tech: &Contact{
				ID:      "GR283-FRNIC",
				Name:    "GANDI ROLE",
				Email:   "noc@gandi.net",
				Country: "FR",
				Street:  []string{"Gandi", "15, place de la Nation", "75011 Paris"},
			},
		},
	}

	checkParserResult(t, "whois.nic.fr", "fr/case2.txt", "fr", exp)
}
