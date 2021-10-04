package server

import (
	"context"
	"net"
	"time"
)

// Resolver controls lookups ips for given domain
type Resolver struct {
	resolver *net.Resolver
	timeout  time.Duration
}

// IP is the output structure for ips in InternalWhoisResp
type IP struct {
	Type string `json:"type,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// NewResolver initializes resolver and lookup timeout
func NewResolver(timeout time.Duration) *Resolver {
	return &Resolver{
		resolver: &net.Resolver{},
		timeout:  timeout,
	}
}

// Lookup lookups ipv4s and ipv6s for given domain, return in API output format
func (ip *Resolver) Lookup(ctx context.Context, domain string, tsFmt string) (ips []IP, err error) {
	ctx, cancel := context.WithTimeout(ctx, ip.timeout)
	defer cancel()
	ips = []IP{}
	var iprecords []net.IP
	if iprecords, err = ip.resolver.LookupIP(ctx, "ip", domain); err == nil {
		for _, ip := range iprecords {
			if ip.To4() != nil {
				ips = append(ips, IP{
					Type: "ipv4",
					IP:   ip.String(),
				})
			} else {
				ips = append(ips, IP{
					Type: "ipv6",
					IP:   ip.String(),
				})
			}
		}
	}
	return
}
