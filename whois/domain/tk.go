package domain

import (
	"sort"
	"strings"
)

var TKMap = map[string]string{
	"Domain registered":     "created_date",
	"Record will expire on": "expired_date",
}

var tkContactKeyMap = map[string]string{
	"zipcode": "postal",
	"e-mail":  "email",
	"address": "street",
}

type TKParser struct{}

type TKTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewTKTLDParser() *TKTLDParser {
	return &TKTLDParser{
		parser: NewParser(),
	}
}

func (tkw *TKTLDParser) GetName() string {
	return "tk"
}

func (tkw *TKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := tkw.parser.Do(rawtext, nil, TKMap)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "Domain name":
			parsedWhois.DomainName = strings.TrimRight(strings.TrimSpace(lines[idx+1]), " is Active")
		case "Owner contact":
			contactFlg = REGISTRANT
			contactsMap[REGISTRANT] = make(map[string]interface{})
		case "Admin contact":
			contactFlg = ADMIN
			contactsMap[ADMIN] = make(map[string]interface{})
		case "Billing contact":
			contactFlg = BILLING
			contactsMap[BILLING] = make(map[string]interface{})
		case "Tech contact":
			contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
		case "Domain Nameservers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "Name", "Organization", "Phone", "Fax", "E-mail",
			"Address", "City", "Zipcode", "Country", "State":
			if len(contactFlg) == 0 {
				continue
			}
			lckey := strings.ToLower(key)
			ckey, ok := tkContactKeyMap[lckey]
			if !ok {
				ckey = lckey
			}
			if ckey == "street" {
				if _, ok := contactsMap[contactFlg][ckey]; !ok {
					contactsMap[contactFlg][ckey] = []string{}
				}
				contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
				continue
			}
			contactsMap[contactFlg][ckey] = val
		}

	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
