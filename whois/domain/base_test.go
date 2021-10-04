package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewWhois(t *testing.T) {
	w := NewWhois(nil, "abc", "whois.nic.aaa")
	assert.Equal(t, "abc", w.RawText)
	assert.Equal(t, "whois.nic.aaa", w.WhoisServer)
}
