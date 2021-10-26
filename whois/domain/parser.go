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
)

var dayReplacer = strings.NewReplacer("st", "", "nd", "", "rd", "", "th", "")

var DefaultKeyMap map[string]string = map[string]string{
	"Domain Name":                            "domain",
	"Domain name":                            "domain",
	"domain":                                 "domain",
	"Domain":                                 "domain",
	"Name Server":                            "name_servers",
	"nserver":                                "name_servers",
	"Nameserver":                             "name_servers",
	"Creation Date":                          "created_date",
	"created":                                "created_date",
	"Created":                                "created_date",
	"Created On":                             "created_date",
	"Registered on":                          "created_date",
	"Registration Time":                      "created_date",
	"Registered":                             "created_date",
	"Updated Date":                           "updated_date",
	"Last updated":                           "updated_date",
	"modified":                               "updated_date",
	"Updated":                                "updated_date",
	"Last Updated On":                        "updated_date",
	"Last modified":                          "updated_date",
	"Registry Expiry Date":                   "expired_date",
	"expires":                                "expired_date",
	"Expiration Date":                        "expired_date",
	"Expiry date":                            "expired_date",
	"paid-till":                              "expired_date",
	"Valid Until":                            "expired_date",
	"Registrar Registration Expiration Date": "expired_date",
	"Expiration Time":                        "expired_date",
	"Expires":                                "expired_date",
	"Domain Status":                          "statuses",
	"Status":                                 "statuses",
	"status":                                 "statuses",
	"DNSSEC":                                 "dnssec",
	"Registrar IANA ID":                      "reg/iana_id",
	"Registrar":                              "reg/name",
	"registrar":                              "reg/name",
	"Sponsoring Registrar":                   "reg/name",
	"Registrar Abuse Contact Email":          "reg/abuse_contact_email",
	"Registrar Abuse Contact Phone":          "reg/abuse_contact_phone",
	"Registrar URL":                          "reg/url",
	"Whois Server":                           "reg/whois_server",
	"Registrar WHOIS Server":                 "reg/whois_server",
	"Registrant Name":                        "c/registrant/name",
	"Registrant Email":                       "c/registrant/email",
	"Registrant Contact Email":               "c/registrant/email",
	"Registrant Organization":                "c/registrant/organization",
	"Registrant Country":                     "c/registrant/country",
	"Registrant City":                        "c/registrant/city",
	"Registrant Street":                      "c/registrant/street",
	"Registrant State/Province":              "c/registrant/state",
	"Registrant Postal Code":                 "c/registrant/postal",
	"Registrant Phone":                       "c/registrant/phone",
	"Registrant PhoneExt":                    "c/registrant/phone_ext",
	"Registrant Fax":                         "c/registrant/fax",
	"Registrant FaxExt":                      "c/registrant/fax_ext",
	"Admin Name":                             "c/admin/name",
	"Admin Email":                            "c/admin/email",
	"Admin Organization":                     "c/admin/organization",
	"Admin Country":                          "c/admin/country",
	"Admin City":                             "c/admin/city",
	"Admin Street":                           "c/admin/street",
	"Admin State/Province":                   "c/admin/state",
	"Admin Postal Code":                      "c/admin/postal",
	"Admin Phone":                            "c/admin/phone",
	"Admin PhoneExt":                         "c/admin/phone_ext",
	"Admin Fax":                              "c/admin/fax",
	"Admin FaxExt":                           "c/admin/fax_ext",
	"Tech Name":                              "c/tech/name",
	"Tech Email":                             "c/tech/email",
	"Tech Organization":                      "c/tech/organization",
	"Tech Country":                           "c/tech/country",
	"Tech City":                              "c/tech/city",
	"Tech Street":                            "c/tech/street",
	"Tech State/Province":                    "c/tech/state",
	"Tech Postal Code":                       "c/tech/postal",
	"Tech Phone":                             "c/tech/phone",
	"Tech PhoneExt":                          "c/tech/phone_ext",
	"Tech Fax":                               "c/tech/fax",
	"Tech FaxExt":                            "c/tech/fax_ext",
	"Billing Name":                           "c/billing/name",
	"Billing Email":                          "c/billing/email",
	"Billing Organization":                   "c/billing/organization",
	"Billing Country":                        "c/billing/country",
	"Billing City":                           "c/billing/city",
	"Billing Street":                         "c/billing/street",
	"Billing State/Province":                 "c/billing/state",
	"Billing Postal Code":                    "c/billing/postal",
	"Billing Phone":                          "c/billing/phone",
	"Billing PhoneExt":                       "c/billing/phone_ext",
	"Billing Fax":                            "c/billing/fax",
	"Billing FaxExt":                         "c/billing/fax_ext",
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
//		parser := NewTLDDomainParser(tld)
//		parsedWhois, err := parser.GetParsedWhois(rawtext)
func NewTLDDomainParser(tld string) ITLDParser {
	switch tld {
	case "ar", "blogspot.com.ar", "com.ar", "edu.ar", "gob.ar",
		"gov.ar", "int.ar", "mil.ar", "net.ar", "org.ar", "tur.ar":
		return NewARTLDParser() // whois.nic.ar
	case "am":
		return NewAMTLDParser() // whois.amnic.net
	case "as":
		return NewASTLDParser() // whois.nic.as
	case "sk":
		return NewSKTLDParser() // whois.sk-nic.sk
	case "uk", "co.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk",
		"ac.uk", "gov.uk":
		return NewUKTLDParser() // whois.nic.uk, whois.ja.net
	case "ua", "com.ua", "in.ua", "kh.ua", "kiev.ua", "lg.ua", "lviv.ua", "net.ua", "org.ua":
		return NewUATLDParser() // whois.ua, whois.net.ua, whois.in.ua
	case "tk":
		return NewTKTLDParser() // whois.dot.tk
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
			ns := strings.Split(val, " ")[0]
			if _, ok := wMap[keyName]; !ok {
				wMap[keyName] = []string{}
			}
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
		if stopFunc != nil && stopFunc(line) {
			break
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}

		// Fill whois map using default key map
		if keyName, ok := DefaultKeyMap[key]; ok {
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
	kw := strings.SplitN(strings.TrimSpace(line), ":", 2)
	if len(kw) != 2 {
		return "", "", errors.New("not valid line")
	}
	return strings.TrimSpace(kw[0]), strings.TrimSpace(kw[1]), nil
}
