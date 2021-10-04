package ip

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/shlin168/go-whois/whois/ip/testdata"
)

func TestDefaultIPParser(t *testing.T) {
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
				Origin: "AS3269",
				Route:  "80.20.0.0/16",
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

func TestWhoisNotFoundIP(t *testing.T) {
	assert.True(t, WhoisNotFound("No data found"))
	assert.False(t, WhoisNotFound("found"))
}
