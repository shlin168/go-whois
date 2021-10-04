package domain

import (
	"github.com/shlin168/go-whois/whois/domain/testdata"
	"github.com/shlin168/go-whois/whois/utils"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUKParser(t *testing.T) {
	exp := &ParsedWhois{
		DomainName: "abc.co.uk",
		Registrar: &Registrar{
			Name: "Moose Internet Services Ltd t/a Moose Internet Services [Tag = MOOSE]",
			URL:  "http://www.moose.co.uk",
		},
		NameServers: []string{
			"ns1.moose.co.uk 85.91.32.11", "ns2.moose.co.uk 85.91.37.37", "ns3.moose.co.uk 185.14.88.117", "ns4.moose.co.uk 185.14.88.117",
		},
		CreatedDateRaw: "before Aug-1996",
		CreatedDate:    "", // invalid format...
		UpdatedDateRaw: "05-Nov-2019",
		UpdatedDate:    "2019-11-05T00:00:00+00:00",
		ExpiredDateRaw: "02-Dec-2021",
		ExpiredDate:    "2021-12-02T00:00:00+00:00",
	}

	parser := NewTLDDomainParser(utils.GetTLD("abc.co.uk"))
	assert.Equal(t, "uk", parser.GetName())

	b, err := testdata.ReadRawtext("uk/case1.txt")
	require.Nil(t, err)
	parsedWhois, err := parser.GetParsedWhois(string(b))
	assert.Nil(t, err)
	assert.Empty(t, cmp.Diff(exp, parsedWhois))
}
