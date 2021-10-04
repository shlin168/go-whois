package domain

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/shlin168/go-whois/whois/domain/testdata"
	"github.com/shlin168/go-whois/whois/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSKParser(t *testing.T) {
	ra := &Contact{
		Name:         "Amazon Europe Core S.a.r.l.",
		Email:        "hostmaster@amazon.com",
		Organization: "Amazon Europe Core S.a.r.l.",
		Country:      "LU",
		City:         "Luxembourg",
		Street:       []string{"38 avenue John F. Kennedy"},
		Phone:        "+352.265240000",
	}
	tech := &Contact{
		Name:         "Technical Manager",
		Email:        "hostmaster@comlaude.com",
		Organization: "Com Laude",
		Country:      "UK",
		City:         "London",
		Street:       []string{"28-30 Little Russell Street"},
		State:        "London",
		Phone:        "+44.2074218250",
	}
	exp := &ParsedWhois{
		DomainName: "amazon.sk",
		Registrar: &Registrar{
			Name:              "Lorna J. Gradden",
			AbuseContactEmail: "hostmaster@comlaude.com",
			AbuseContactPhone: "+44.2074218250",
		},
		NameServers:    []string{"nsgbr.comlaude.co.uk", "nssui.comlaude.ch", "nsusa.comlaude.net"},
		CreatedDateRaw: "2003-11-12",
		CreatedDate:    "2003-11-12T00:00:00+00:00",
		UpdatedDateRaw: "2020-11-07",
		UpdatedDate:    "2020-11-07T00:00:00+00:00",
		ExpiredDateRaw: "2021-11-12",
		ExpiredDate:    "2021-11-12T00:00:00+00:00",
		Statuses:       []string{"clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"},
		Contacts: &Contacts{
			Registrant: ra,
			Admin:      ra,
			Tech:       tech,
		},
	}

	parser := NewTLDDomainParser(utils.GetTLD("amazon.sk"))
	assert.Equal(t, "sk", parser.GetName())

	b, err := testdata.ReadRawtext("sk/case1.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.GetParsedWhois(string(b))
	assert.Nil(t, err)
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}
