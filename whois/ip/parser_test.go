package ip

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-whois/whois/ip/testdata"
)

func TestDefaultIPParserRIPE(t *testing.T) {
	exp := &ParsedWhois{
		Networks: []Network{
			{
				Inetnum: "80.20.134.0 - 80.20.134.255",
				Range: &Range{
					From: "80.20.134.0",
					To:   "80.20.134.255",
				},
				Netname: "INTERBUSINESS",
				Contact: Contact{
					Country:        "IT",
					Description:    []string{"Telecom Italia SPA", "Provider Local Registry", "BB IBS"},
					Remarks:        []string{"INFRA-AW"},
					ContactAdmin:   []string{"INAS1-RIPE"},
					ContactTech:    []string{"INAS1-RIPE"},
					MntBy:          []string{"INTERB-MNT"},
					UpdatedDate:    "2003-05-28T07:38:46+00:00",
					UpdatedDateRaw: "2003-05-28T07:38:46Z",
					Source:         "RIPE # Filtered",
				},
			},
		},
		Contacts: []Contact{
			{
				ID:             "INAS1-RIPE",
				Type:           "role",
				Name:           "Interbusiness Network Administration Staff",
				Address:        []string{"Telecom Italia S.p.A", "Italy"},
				ContactAdmin:   []string{"ESB35-RIPE"},
				ContactTech:    []string{"ESB35-RIPE", "ASB144-RIPE", "SSB86-RIPE", "DSB58-RIPE", "ABT49-RIPE"},
				AbuseMailbox:   []string{"abuse@business.telecomitalia.it"},
				MntBy:          []string{"INTERB-MNT"},
				UpdatedDate:    "2018-05-24T06:06:48+00:00",
				UpdatedDateRaw: "2018-05-24T06:06:48Z",
				Source:         "RIPE # Filtered",
			},
		},
		Routes: []Route{
			{
				OriginAS: "AS3269",
				Route:    "80.20.0.0/16",
				Contact: Contact{
					ID:          "80.20.0.0/16",
					Type:        "route",
					Description: []string{"INTERBUSINESS"},
					Remarks: []string{
						"************************************************",
						"* Pay attention *",
						"* Any communication sent to email different *",
						"* from the following will be ignored! *",
						"* Any abuse reports, please send them to *",
						"* abuse@business.telecomitalia.it *",
						"************************************************",
					},
					MntBy:          []string{"INTERB-MNT"},
					UpdatedDateRaw: "2017-07-17T12:27:54Z",
					UpdatedDate:    "2017-07-17T12:27:54+00:00",
					Source:         "RIPE # Filtered",
				},
			},
		},
	}
	parser := NewParser("80.20.134.34", logrus.New())

	b, err := testdata.ReadRawtext("default/ripe.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.Do(string(b))
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestDefaultIPParserARIN(t *testing.T) {
	exp := &ParsedWhois{
		Networks: []Network{
			{
				Inetnum: "20.0.0.0 - 20.31.255.255",
				Range: &Range{
					From: "20.0.0.0",
					To:   "20.31.255.255",
					CIDR: []string{"20.0.0.0/11"},
				},
				Netname: "MSFT",
				Parent:  "NET20 (NET-20-0-0-0-0)",
				Contact: Contact{
					UpdatedDate:    "2017-10-18T00:00:00+00:00",
					UpdatedDateRaw: "2017-10-18",
					Ref:            []string{"https://rdap.arin.net/registry/ip/20.0.0.0"},
				},
			},
		},
		Contacts: []Contact{
			{
				ID:      "MSFT",
				Type:    "org",
				Name:    "Microsoft Corporation",
				Address: []string{"One Microsoft Way"},
				Country: "US",
				Description: []string{
					"To report suspected security issues specific to traffic emanating from Microsoft online services, including the distribution of malicious content or other illicit or illegal material through a Microsoft online service, please submit reports to:",
					"* https://cert.microsoft.com.",
					"",
					"For SPAM and other abuse issues, such as Microsoft Accounts, please contact:",
					"* abuse@microsoft.com.",
					"",
					"To report security vulnerabilities in Microsoft products and services, please contact:",
					"* secure@microsoft.com.",
					"",
					"For legal and law enforcement-related requests, please contact:",
					"* msndcc@microsoft.com",
					"",
					"For routing, peering or DNS issues, please",
					"contact:",
					"* IOC@microsoft.com",
				},
				Ref:            []string{"https://rdap.arin.net/registry/entity/MSFT"},
				UpdatedDate:    "2021-10-13T00:00:00+00:00",
				UpdatedDateRaw: "2021-10-13",
			},
			{
				ID:    "IPHOS5-ARIN",
				Type:  "org-tech",
				Name:  "IPHostmaster, IPHostmaster",
				Phone: []string{"+1-425-538-6637"},
				Email: []string{"iphostmaster@microsoft.com"},
				Ref:   []string{"https://rdap.arin.net/registry/entity/IPHOS5-ARIN"},
			},
			{
				ID:    "MAC74-ARIN",
				Type:  "org-abuse",
				Name:  "Microsoft Abuse Contact",
				Phone: []string{"+1-425-882-8080"},
				Email: []string{"abuse@microsoft.com"},
				Ref:   []string{"https://rdap.arin.net/registry/entity/MAC74-ARIN"},
			},
			{
				ID:    "MRPD-ARIN",
				Type:  "org-tech",
				Name:  "Microsoft Routing, Peering, and DNS",
				Phone: []string{"+1-425-882-8080"},
				Email: []string{"IOC@microsoft.com"},
				Ref:   []string{"https://rdap.arin.net/registry/entity/MRPD-ARIN"},
			},
			{
				ID:    "YSRH-ARIN",
				Type:  "org-dns",
				Name:  "Yalamati, Sree Raghu Harsha",
				Phone: []string{"+917702220771"},
				Email: []string{"v-raghuy@microsoft.com"},
				Ref:   []string{"https://rdap.arin.net/registry/entity/YSRH-ARIN"},
			},
		},
	}
	parser := NewParser("20.13.58.30", logrus.New())

	b, err := testdata.ReadRawtext("default/arin.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.Do(string(b))
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestDefaultIPParserAPNIC(t *testing.T) {
	exp := &ParsedWhois{
		Networks: []Network{
			{
				Inetnum: "110.8.0.0 - 110.15.255.255",
				Range: &Range{
					From: "110.8.0.0",
					To:   "110.15.255.255",
				},
				Netname: "broadNnet",
				MntIrt:  "IRT-KRNIC-KR",
				Contact: Contact{
					Country:        "KR",
					Description:    []string{"SK Broadband Co Ltd"},
					ContactAdmin:   []string{"IM670-AP"},
					ContactTech:    []string{"IM670-AP"},
					MntBy:          []string{"MNT-KRNIC-AP"},
					UpdatedDate:    "2017-02-03T00:38:16+00:00",
					UpdatedDateRaw: "2017-02-03T00:38:16Z",
					Source:         "APNIC",
				},
			},
			{
				Inetnum: "110.8.0.0 - 110.15.255.255",
				Range: &Range{
					From: "110.8.0.0",
					To:   "110.15.255.255",
				},
				Netname: "broadNnet-KR",
				MntIrt:  "IRT-KRNIC-KR",
				Contact: Contact{
					Country:     "KR",
					Description: []string{"SK Broadband Co Ltd"},
					Remarks: []string{
						"This information has been partially mirrored by APNIC from",
						"KRNIC. To obtain more specific information, please use the",
						"KRNIC whois server at whois.kisa.or.kr.",
					},
					ContactAdmin: []string{"IM12-KR"},
					ContactTech:  []string{"IM12-KR"},
					MntBy:        []string{"MNT-KRNIC-AP"},
					Source:       "KRNIC",
				},
			},
		},
		Contacts: []Contact{
			{
				ID:             "IRT-KRNIC-KR",
				Type:           "irt",
				Address:        []string{"Jeollanam-do Naju-si Jinheung-gil"},
				Email:          []string{"irt@nic.or.kr"},
				Remarks:        []string{"irt@nic.or.kr was validated on 2020-04-09"},
				ContactAdmin:   []string{"IM574-AP"},
				ContactTech:    []string{"IM574-AP"},
				AbuseMailbox:   []string{"irt@nic.or.kr"},
				MntBy:          []string{"MNT-KRNIC-AP"},
				Auth:           []string{"# Filtered"},
				UpdatedDate:    "2021-06-15T06:21:49+00:00",
				UpdatedDateRaw: "2021-06-15T06:21:49Z",
				Source:         "APNIC",
			},
			{
				ID:             "IM670-AP",
				Type:           "person",
				Name:           "IP Manager",
				Address:        []string{"Seoul Jung-gu Toegye-ro 24"},
				Country:        "KR",
				Phone:          []string{"+82-80-828-2106"},
				Email:          []string{"ip-adm@skbroadband.com"},
				MntBy:          []string{"MNT-KRNIC-AP"},
				UpdatedDate:    "2021-10-05T05:20:03+00:00",
				UpdatedDateRaw: "2021-10-05T05:20:03Z",
				Source:         "APNIC",
			},
			{
				ID:      "IM12-KR",
				Type:    "person",
				Name:    "IP Manager",
				Address: []string{"Seoul Jung-gu Toegye-ro 24", "SK Namsan Green Bldg."},
				Country: "KR",
				Phone:   []string{"+82-80-828-2106"},
				Email:   []string{"ip-adm@skbroadband.com"},
				MntBy:   []string{"MNT-KRNIC-AP"},
				Source:  "KRNIC",
			},
		},
	}
	parser := NewParser("110.13.60.20", logrus.New())

	b, err := testdata.ReadRawtext("default/apnic.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.Do(string(b))
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestDefaultIPParserLACNIC(t *testing.T) {
	exp := &ParsedWhois{
		Networks: []Network{
			{
				Inetnum: "200.68.34.56/29",
				Range: &Range{
					CIDR: []string{"200.68.34.56/29"},
				},
				Org:      "Agencia de Aduanas Patricio Sesnich Stewart y Comp",
				OriginAS: "N/A",
				Parent:   "200.68.34.0/24",
				Contact: Contact{
					Address:        []string{"San Martin, 50, Piso 6", "8340526 - Santiago - RM"},
					Country:        "CL",
					Phone:          []string{"+56 2 7701400"},
					ContactTech:    []string{"OTE"},
					UpdatedDate:    "2010-01-28T00:00:00+00:00",
					UpdatedDateRaw: "20100128",
				},
			},
		},
		Contacts: []Contact{
			{
				ID:             "OTE",
				Type:           "person",
				Name:           "Operaciones Telefonica Internet Empresas",
				Address:        []string{"San Martin 50, Piso 5, 50,", "02 - Santiago - RM"},
				Country:        "CL",
				Email:          []string{"oper@isp.tie.cl"},
				Phone:          []string{"+56 02 6911620"},
				UpdatedDate:    "2006-02-15T00:00:00+00:00",
				UpdatedDateRaw: "20060215",
			},
		},
	}
	parser := NewParser("200.68.34.62", logrus.New())

	b, err := testdata.ReadRawtext("default/lacnic.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.Do(string(b))
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestDefaultIPParserAFRINIC(t *testing.T) {
	exp := &ParsedWhois{
		Networks: []Network{
			{
				Inetnum: "105.158.0.0 - 105.158.255.255",
				Range: &Range{
					From: "105.158.0.0",
					To:   "105.158.255.255",
				},
				Netname: "ADSL_Maroc_telecom",
				Parent:  "105.128.0.0 - 105.159.255.255",
				Contact: Contact{
					Country:      "MA",
					Description:  []string{"ADSL_Maroc_telecom"},
					ContactAdmin: []string{"DMT1-AFRINIC"},
					ContactTech:  []string{"SMT1-AFRINIC"},
					MntBy:        []string{"ONPT-MNT"},
					Source:       "AFRINIC # Filtered",
				},
			},
		},
		Contacts: []Contact{
			{
				ID:   "DMT1-AFRINIC",
				Type: "person",
				Name: "DEMPFS Maroc Telecom",
				Address: []string{
					"Division Exploitation et maintenance des PFS",
					"MAROC TELECOM",
					"Avenue de France AGDAL",
					"Immeuble DR Rabat",
				},
				Phone:  []string{"tel:+212-37686318"},
				MntBy:  []string{"GENERATED-59UQAQ1UAZKQWKK5GWNQRJ9VGMHDFDGD-MNT"},
				Source: "AFRINIC # Filtered",
			},
			{
				ID:   "SMT1-AFRINIC",
				Type: "person",
				Name: "SEPFS Maroc Telecom",
				Address: []string{
					"Service Exploitation des PFS",
					"MAROC TELECOM",
					"Avenue Hay Annakhil Riad",
					"rabat",
					"Morocco",
				},
				Phone:  []string{"tel:+212-37284314", "tel:+212-37284319"},
				MntBy:  []string{"GENERATED-QKJHRQGRJU8KJEZGF62S2JCUXLD0D81A-MNT"},
				Source: "AFRINIC # Filtered",
			},
		},
		Routes: []Route{
			{
				OriginAS: "AS36903",
				Route:    "105.128.0.0/11",
				Contact: Contact{
					ID:          "105.128.0.0/11",
					Type:        "route",
					MntBy:       []string{"ONPT-MNT"},
					Description: []string{"route object"},
					Source:      "AFRINIC # Filtered",
				},
			},
			{
				OriginAS: "AS6713",
				Route:    "105.128.0.0/11",
				Contact: Contact{
					ID:          "105.128.0.0/11",
					Type:        "route",
					MntBy:       []string{"ONPT-MNT"},
					Description: []string{"route object"},
					Source:      "AFRINIC # Filtered",
				},
			},
		},
	}
	parser := NewParser("105.158.104.112", logrus.New())

	b, err := testdata.ReadRawtext("default/afrinic.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.Do(string(b))
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}

func TestWhoisNotFoundIP(t *testing.T) {
	assert.True(t, WhoisNotFound("No data found"))
	assert.False(t, WhoisNotFound("found"))
}
