package utils

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrInArray(t *testing.T) {
	if !StrInArray("abc", []string{"abc", "cde", "efg"}) {
		t.Fatal("should return true")
	}
	if StrInArray("123", []string{"abc", "cde", "efg"}) {
		t.Fatal("should return false")
	}
}

func TestGetPublicSuffixs(t *testing.T) {
	var emptyResult []string
	for _, ts := range []struct {
		domain string
		exp    []string
		err    error
	}{
		{"foo.bar.golang.org", []string{"golang.org"}, nil},
		// query 3-level first if it's ICANN-managed domain
		{"frolic.yalta.ua", []string{"frolic.yalta.ua", "yalta.ua"}, nil},
		{"ndekc.zhitomir.ua", []string{"ndekc.zhitomir.ua", "zhitomir.ua"}, nil},
		{"services.edicon.edu.pl", []string{"edicon.edu.pl", "edu.pl"}, nil},
		{"hsbc.co.mu", []string{"hsbc.co.mu", "co.mu"}, nil},
		{"pooch.co.uk", []string{"pooch.co.uk", "co.uk"}, nil},
		{"abbmal.com.ng", []string{"abbmal.com.ng", "com.ng"}, nil},
		// force query 3-level first even it's not ICANN-managed domain
		{"pancakeswap.co.com", []string{"pancakeswap.co.com", "co.com"}, nil},
		{"gurman.co.ua", []string{"gurman.co.ua", "co.ua"}, nil},
		{"au-eden.parachute.jpn.com", []string{"parachute.jpn.com", "jpn.com"}, nil},
		// only query 2-level for non ICANN-managed domain
		{"abc.github.io", []string{"github.io"}, nil},
		{"delivery.africa.com", []string{"africa.com"}, nil},
		// testing errors
		{"github.io", []string{"github.io"}, errors.New(`publicsuffix: cannot derive eTLD+1 for domain "github.io"`)},
		{"org", emptyResult, errors.New(`publicsuffix: cannot derive eTLD+1 for domain "org"`)},
		{"bbb.bbb", []string{"bbb.bbb"}, errors.New(`level = 1: bbb`)},
	} {
		ps, err := GetPublicSuffixs(ts.domain)
		if err == nil {
			assert.Nil(t, ts.err)
		} else {
			assert.Equal(t, ts.err, err)
		}
		assert.Equal(t, ts.exp, ps)
	}
}

func TestGetHost(t *testing.T) {
	host, err := GetHost("www.abcde.com")
	assert.Nil(t, err)
	assert.Equal(t, "www.abcde.com", host)

	host, err = GetHost("www.abcde.com:80")
	assert.Nil(t, err)
	assert.Equal(t, "www.abcde.com", host)

	// invalid query
	host, err = GetHost("www.google[abc].com:80")
	assert.NotNil(t, err)
	assert.Equal(t, "www.google[abc].com", host)

	host, err = GetHost("www.google[abc].com")
	assert.Nil(t, err)
	assert.Equal(t, "www.google[abc].com", host)
}

func TestGetTLD(t *testing.T) {
	assert.Equal(t, "aaa", GetTLD("aaa.aaa"))
	assert.Equal(t, "co.uk", GetTLD("pooch.co.uk"))
	assert.Equal(t, "com", GetTLD("com"))
}

func TestIsIP(t *testing.T) {
	assert.True(t, IsIP("123.42.64.38"))
	assert.False(t, IsIP("583.42.64.38"))
	assert.False(t, IsIP("google.com"))
}
