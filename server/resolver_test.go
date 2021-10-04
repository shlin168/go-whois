package server

import (
	"context"
	"testing"
	"time"

	wd "github.com/shlin168/go-whois/whois/domain"
	"github.com/stretchr/testify/assert"
)

func TestLookup(t *testing.T) {
	resolver := NewResolver(5 * time.Second)
	ips, err := resolver.Lookup(context.Background(), "www.google.com", wd.WhoisTimeFmt)
	if err != nil {
		t.Skip("Resolver lookup failed, just log without raising error:", err)
		assert.Empty(t, ips)
	} else {
		assert.NotEmpty(t, ips)
	}
}
