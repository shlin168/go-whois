package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

const (
	missingPort = "missing port in address"
)

// GetHost fetch host from "<host>:<port>" string, and return input string if it does not contain port
func GetHost(domain string) (string, error) {
	host, _, err := net.SplitHostPort(domain)
	if err != nil {
		if addrErr, ok := err.(*net.AddrError); ok {
			switch addrErr.Err {
			case missingPort:
				// input only contains host name, mute the error
				return domain, nil
			default:
				if hp := strings.Split(domain, ":"); len(hp) > 1 {
					return hp[0], err
				}
				return addrErr.Addr, err
			}
		} else {
			return domain, err
		}
	}
	return host, nil
}

// If length of all the items in public suffix less than 3, force query publicsuffix + 1 first
// no matter it's ICANN-managed domain or not
// E.g. "co.uk", "jpn.com", "net.ua" -> true
// E.g. "github.io", "zhitomir.ua" -> false
func ForceQueryThreeLevel(ps string) bool {
	for _, tlditem := range strings.Split(ps, ".") {
		if len(tlditem) > 3 {
			return false
		}
	}
	return true
}

// GetPublicSuffixs returns public suffixs of input domain
func GetPublicSuffixs(domain string) ([]string, error) {
	// return publicsuffix + 1 and publicsuffix, remove items if length of tld is less than 2
	var publicSuffixs []string
	publicSuffixPlusOne, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err == nil {
		publicSuffixs = append(publicSuffixs, publicSuffixPlusOne)
	}
	publicSuffix, icann := publicsuffix.PublicSuffix(domain)
	if !icann {
		// unmanaged top-level domain, return publicsuffix + 1 directly
		if strings.Index(publicSuffix, ".") == -1 {
			return publicSuffixs, fmt.Errorf("level = 1: %s", publicSuffix)
		}
		if !ForceQueryThreeLevel(publicSuffix) {
			// private domains, only query ps. E.g, github.io
			return []string{publicSuffix}, err
		}
		// There are some TLDs that is not managed by ICANN while it should still query ps+1 first
	}
	if strings.Index(publicSuffix, ".") != -1 && !StrInArray(publicSuffix, publicSuffixs) {
		publicSuffixs = append(publicSuffixs, publicSuffix)
	}
	return publicSuffixs, err
}

// return string after first ".", and return input string if it does not contains "."
// E.g,
// 	GetTLD("aaa.aaa") = "aaa"
// 	GetTLD("pooch.co.uk") = "co.uk"
// 	GetTLD("com") = "com"
func GetTLD(ps string) string {
	if tldlist := strings.SplitN(ps, ".", 2); len(tldlist) == 2 {
		return tldlist[1]
	}
	return ps
}

// StrInArray returns whether item is in array
func StrInArray(val string, arr []string) bool {
	for _, v := range arr {
		if val == v {
			return true
		}
	}
	return false
}

// IsIP return true if input host string is a valid IP
func IsIP(host string) bool {
	addr := net.ParseIP(host)
	if addr != nil {
		return true
	} else {
		return false
	}
}

// IsTimeout return whether an error is classified as **timeout** error
func IsTimeout(err error) bool {
	err = errors.Unwrap(err)
	if err, ok := err.(net.Error); (ok && err.Timeout()) || os.IsTimeout(err) {
		return true
	}
	return false
}
