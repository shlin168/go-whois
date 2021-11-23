package domain

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const (
	CONTACTS = "contacts"

	REGISTRAR = "registrar"

	REGISTRANT = "registrant"
	ADMIN      = "admin"
	TECH       = "tech"
	BILLING    = "billing"

	maxNServer = 20
	maxDStatus = 10
)

var dayReplacer = strings.NewReplacer("st", "", "nd", "", "rd", "", "th", "")

func mapRawtextKeyToStructKey(key string) string {
	if val, ok := defaultKeyMap[strings.ToLower(key)]; ok {
		return val
	}
	return ""
}

var defaultKeyMap map[string]string = map[string]string{
	"domain name":                            "domain",
	"domain":                                 "domain",
	"name server":                            "name_servers",
	"nserver":                                "name_servers",
	"nameserver":                             "name_servers",
	"nameservers":                            "name_servers",
	"creation date":                          "created_date",
	"created":                                "created_date",
	"created on":                             "created_date",
	"registered on":                          "created_date",
	"registration time":                      "created_date",
	"registered":                             "created_date",
	"updated date":                           "updated_date",
	"last updated":                           "updated_date",
	"last update":                            "updated_date",
	"modified":                               "updated_date",
	"updated":                                "updated_date",
	"last updated on":                        "updated_date",
	"last modified":                          "updated_date",
	"registry expiry date":                   "expired_date",
	"expires":                                "expired_date",
	"expiration date":                        "expired_date",
	"expiry date":                            "expired_date",
	"expire date":                            "expired_date",
	"paid-till":                              "expired_date",
	"valid until":                            "expired_date",
	"registrar registration expiration date": "expired_date",
	"expiration time":                        "expired_date",
	"domain status":                          "statuses",
	"status":                                 "statuses",
	"dnssec":                                 "dnssec",
	"registrar iana id":                      "reg/iana_id",
	"registrar":                              "reg/name",
	"sponsoring registrar":                   "reg/name",
	"registrar name":                         "reg/name",
	"registrar abuse contact email":          "reg/abuse_contact_email",
	"registrar abuse contact phone":          "reg/abuse_contact_phone",
	"registrar url":                          "reg/url",
	"whois server":                           "reg/whois_server",
	"registrar whois server":                 "reg/whois_server",
	"registrant name":                        "c/registrant/name",
	"registrant email":                       "c/registrant/email",
	"registrant contact email":               "c/registrant/email",
	"registrant organization":                "c/registrant/organization",
	"registrant country":                     "c/registrant/country",
	"registrant city":                        "c/registrant/city",
	"registrant street":                      "c/registrant/street",
	"registrant state/province":              "c/registrant/state",
	"registrant postal code":                 "c/registrant/postal",
	"registrant phone":                       "c/registrant/phone",
	"registrant phoneExt":                    "c/registrant/phone_ext",
	"registrant fax":                         "c/registrant/fax",
	"registrant faxExt":                      "c/registrant/fax_ext",
	"admin name":                             "c/admin/name",
	"admin email":                            "c/admin/email",
	"admin organization":                     "c/admin/organization",
	"admin country":                          "c/admin/country",
	"admin city":                             "c/admin/city",
	"admin street":                           "c/admin/street",
	"admin state/province":                   "c/admin/state",
	"admin postal code":                      "c/admin/postal",
	"admin phone":                            "c/admin/phone",
	"admin phoneext":                         "c/admin/phone_ext",
	"admin fax":                              "c/admin/fax",
	"admin faxext":                           "c/admin/fax_ext",
	"tech name":                              "c/tech/name",
	"tech email":                             "c/tech/email",
	"tech organization":                      "c/tech/organization",
	"tech country":                           "c/tech/country",
	"tech city":                              "c/tech/city",
	"tech street":                            "c/tech/street",
	"tech state/province":                    "c/tech/state",
	"tech postal code":                       "c/tech/postal",
	"tech phone":                             "c/tech/phone",
	"tech phoneext":                          "c/tech/phone_ext",
	"tech fax":                               "c/tech/fax",
	"tech faxext":                            "c/tech/fax_ext",
	"billing name":                           "c/billing/name",
	"billing email":                          "c/billing/email",
	"billing organization":                   "c/billing/organization",
	"billing country":                        "c/billing/country",
	"billing city":                           "c/billing/city",
	"billing street":                         "c/billing/street",
	"billing state/province":                 "c/billing/state",
	"billing postal code":                    "c/billing/postal",
	"billing phone":                          "c/billing/phone",
	"billing phoneext":                       "c/billing/phone_ext",
	"billing fax":                            "c/billing/fax",
	"billing faxext":                         "c/billing/fax_ext",
}

var notFoundMsg = []string{
	"no data found",
	"not found",
	"no match",
	"not registered",
	"no object found",
	"object does not exist",
	"nothing found",
	"no entries found",
	"but this server does not have", // whois.iana.org
}

// IParser is used to parse whois information when input is domain
type IParser interface {
	Do(string, func(string) bool, ...map[string]string) (*ParsedWhois, error)
}

// ITLDParser might have differenet parsing behavior depends on parameters sent to IParser.Do
type ITLDParser interface {
	GetParsedWhois(string) (*ParsedWhois, error)
	GetName() string
}

// NewTLDDomainParser return different parser for different TLD
// If adding new parser for specific TLDs, new case match should be added to this function
// Usage:
//		parser := NewTLDDomainParser(whois_server)
//		parsedWhois, err := parser.GetParsedWhois(rawtext)
func NewTLDDomainParser(whoisServer string) ITLDParser {
	switch whoisServer {
	case "whois.nic.ar":
		return NewARTLDParser() // ar
	case "whois.amnic.net":
		return NewAMTLDParser() // am
	case "whois.nic.as":
		return NewASTLDParser() // as
	case "whois.nic.at":
		return NewATTLDParser() // at
	case "whois.audns.net.au":
		return NewAUTLDParser() // au
	case "whois.dns.be":
		return NewBETLDParser() // be
	case "whois.nic.br":
		return NewBRTLDParser() // br
	case "whois.nic.cz":
		return NewCZTLDParser() // cz
	case "whois.eu":
		return NewEUTLDParser() // eu
	case "whois.nic.fr":
		return NewFRTLDParser() // fr
	case "whois.nic.ir":
		return NewIRTLDParser() // ir
	case "whois.nic.it":
		return NewITTLDParser() // it
	case "whois.domain-registry.nl":
		return NewNLTLDParser() // nl
	case "whois.dns.pl":
		return NewPLTLDParser() // pl
	case "whois.ripn.net":
		return NewRUTLDParser() // ru
	case "whois.sk-nic.sk":
		return NewSKTLDParser() // sk
	case "whois.dot.tk", "whois.dot.ml", "whois.dominio.gq":
		return NewTKMLGQTLDParser() // gq, ml, tk
	case "whois.twnic.net", "whois.twnic.net.tw":
		return NewTWTLDParser() // tw
	case "whois.nic.uk", "whois.ja.net":
		return NewUKTLDParser() // uk
	case "whois.ua", "whois.net.ua", "whois.in.ua":
		return NewUATLDParser() // ua
	default:
		return NewTLDParser()
	}
}

// Parser implements default parser if tlds not match other parsers with specific parsing method
type Parser struct{}

// TLDParser implements default TLD parser which invoke Parser.Do with different parameters
type TLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewParser() *Parser {
	return &Parser{}
}

func NewTLDParser() *TLDParser {
	return &TLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, ">>>") },
	}
}

// GetName return name of TLDParser for logging
func (wtld *TLDParser) GetName() string {
	return "default"
}

// GetParsedWhois invoke Do in parser to parse rawtext
func (wtld *TLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	return wtld.parser.Do(rawtext, wtld.stopFunc)
}

// Do parse rawtext with DefaultKeyMap, stop parsing if stopFunc is given and return true
// If specKeyMaps is given, it will parse
func (wb *Parser) Do(rawtext string, stopFunc func(string) bool, specKeyMaps ...map[string]string) (*ParsedWhois, error) {
	// Initialize map to store whois information
	wMap := make(map[string]interface{})

	// Define function to map key name in raw text to whois json struct tag
	fillWhoisMap := func(keyName, val string, overwriteIfExist bool) {
		// Registrar
		if strings.HasPrefix(keyName, "reg/") {
			if _, ok := wMap[REGISTRAR]; !ok {
				wMap[REGISTRAR] = make(map[string]string)
			}
			kn := strings.TrimLeft(keyName, "reg/")
			wMap[REGISTRAR].(map[string]string)[kn] = val
			return
		}
		// Contacts
		if strings.HasPrefix(keyName, "c/") {
			if _, ok := wMap[CONTACTS]; !ok {
				wMap[CONTACTS] = make(map[string]map[string]interface{})
			}
			for _, cKey := range []string{REGISTRANT, ADMIN, TECH, BILLING} {
				contactPrefix := "c/" + cKey + "/"
				if !strings.HasPrefix(keyName, contactPrefix) {
					continue
				}
				if _, ok := wMap[CONTACTS].(map[string]map[string]interface{})[cKey]; !ok {
					wMap[CONTACTS].(map[string]map[string]interface{})[cKey] = make(map[string]interface{})
				}
				contactFieldKey := keyName[len(contactPrefix):]
				switch contactFieldKey {
				case "street":
					if _, ok := wMap[CONTACTS].(map[string]map[string]interface{})[cKey][contactFieldKey]; !ok {
						wMap[CONTACTS].(map[string]map[string]interface{})[cKey][contactFieldKey] = []string{}
					}
					wMap[CONTACTS].(map[string]map[string]interface{})[cKey][contactFieldKey] = append(
						wMap[CONTACTS].(map[string]map[string]interface{})[cKey][contactFieldKey].([]string), val)
				default:
					wMap[CONTACTS].(map[string]map[string]interface{})[cKey][contactFieldKey] = val
				}
			}
			return
		}
		switch keyName {
		case "statuses":
			// Trim link in status
			// E.g., clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
			if _, ok := wMap[keyName]; !ok {
				wMap[keyName] = []string{}
			}
			// if contains ",", split by ","
			if strings.Index(val, ",") != -1 {
				for _, ns := range strings.Split(val, ",") {
					wMap[keyName] = append(wMap[keyName].([]string), strings.TrimSpace(ns))
				}
				return
			}
			ns := strings.Split(val, " ")[0]
			wMap[keyName] = append(wMap[keyName].([]string), ns)
		case "name_servers":
			if _, ok := wMap[keyName]; !ok {
				wMap[keyName] = []string{}
			}
			wMap[keyName] = append(wMap[keyName].([]string), val)
		default:
			if overwriteIfExist {
				wMap[keyName] = val
			} else {
				if _, ok := wMap[keyName]; !ok {
					wMap[keyName] = val
				}
			}
		}
	}

	// Parsing raw text line by line
	for _, line := range strings.Split(rawtext, "\n") {
		line = strings.TrimSpace(line)
		if IsCommentLine(line) {
			continue
		}
		if stopFunc != nil && stopFunc(line) {
			break
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}

		// Fill whois map using default key map
		if keyName := mapRawtextKeyToStructKey(key); len(keyName) > 0 {
			fillWhoisMap(keyName, val, false)
		}
		// Add special key maps to enrich default parsing result,
		// which is useful for different TLDs to handle rawtext in different ways
		if len(specKeyMaps) > 0 {
			for _, specKeyMap := range specKeyMaps {
				if keyName, ok := specKeyMap[key]; ok {
					fillWhoisMap(keyName, val, true)
				}
			}
		}
	}
	parsedWhois, err := map2ParsedWhois(wMap)
	if err != nil {
		return nil, err
	}

	// Since '...DateRaw' fields do not contains json struct tag, actual values are temporarily
	// stored in '...Date' fields. Manually copied them back and try to parse date fields
	parsedWhois.CreatedDateRaw = parsedWhois.CreatedDate
	parsedWhois.UpdatedDateRaw = parsedWhois.UpdatedDate
	parsedWhois.ExpiredDateRaw = parsedWhois.ExpiredDate
	parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)

	sort.Strings(parsedWhois.NameServers)
	sort.Strings(parsedWhois.Statuses)
	return parsedWhois, nil
}

func map2ParsedWhois(wMap map[string]interface{}) (*ParsedWhois, error) {
	// Marshal from map and unmarshal to Whois Struct
	jsoncontent, err := json.Marshal(wMap)
	if err != nil {
		return nil, err
	}
	w := ParsedWhois{}
	if err := json.Unmarshal(jsoncontent, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func map2ParsedContacts(cMap map[string]map[string]interface{}) (*Contacts, error) {
	jsoncontent, err := json.Marshal(cMap)
	if err != nil {
		return nil, err
	}
	w := Contacts{}
	if err := json.Unmarshal(jsoncontent, &w); err != nil {
		return nil, err
	}
	return &w, nil
}

func mapContactKeys(cKeyMap map[string]string, key string) string {
	if val, ok := cKeyMap[key]; ok {
		return val
	}
	return key
}

// FoundByKey return value of key from rawtext
// 		FoundByKey("whois server", "whois server: whois.nic.aaa") = whois.nic.aaa
func FoundByKey(key, rawtext string) string {
	keyPlusColon := key + ":"
	if startIdx := strings.Index(rawtext, keyPlusColon); startIdx != -1 {
		startIdx += len(keyPlusColon)
		if endIdx := strings.Index(rawtext[startIdx:], "\n"); endIdx != -1 {
			return strings.TrimSpace(rawtext[startIdx : startIdx+endIdx])
		}
	}
	return ""
}

// WhoisNotFound check keywords in rawtext
func WhoisNotFound(rawtext string) bool {
	rw := strings.ToLower(rawtext)
	for _, kw := range notFoundMsg {
		if strings.Index(rw, kw) != -1 {
			return true
		}
	}
	return false
}

func getKeyValFromLine(line string) (key, val string, err error) {
	line = strings.TrimSpace(line)
	kw := strings.SplitN(line, ":", 2)
	if len(kw) < 2 {
		return line, "", errors.New("not valid line")
	}
	return strings.TrimSpace(kw[0]), strings.TrimSpace(kw[1]), nil
}

func IsCommentLine(line string) bool {
	return strings.HasPrefix(line, "%") || strings.HasPrefix(line, "*")
}
