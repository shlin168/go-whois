package whois

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDomainWhoisServerMap(t *testing.T) {
	sMap, err := NewDomainWhoisServerMap(WhoisServerListURL)
	assert.Nil(t, err)
	assert.Equal(t, "whois.nic.abc", sMap["abc"][0].Host)

	exp, err := regexp.Compile("\\Qno match\\E")
	require.Nil(t, err)
	assert.Equal(t, exp, sMap["abc"][0].AvailPtn)

	// test get whois server
	assert.Equal(t, "whois.nic.uk", sMap.GetWhoisServer("pooch.co.uk")[0].Host)
	assert.Equal(t, "whois.nic.uk", sMap.GetWhoisServer("co.uk")[0].Host)
	assert.Equal(t, 0, len(sMap.GetWhoisServer("abcdef")))
}
