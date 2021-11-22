package domain

import (
	"sort"
	"strings"
)

var TKMLGQMap = map[string]string{
	"Domain registered":     "created_date",
	"Record will expire on": "expired_date",
}

var tkmlgqContactKeyMap = map[string]string{
	"zipcode": "postal",
	"e-mail":  "email",
	"address": "street",
}

type TKMLGQParser struct{}

type TKMLGQTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewTKMLGQTLDParser() *TKMLGQTLDParser {
	return &TKMLGQTLDParser{
		parser: NewParser(),
	}
}

func (tkmlgqw *TKMLGQTLDParser) GetName() string {
	return "tk/ml/gq"
}

func (tkmlgqw *TKMLGQTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := tkmlgqw.parser.Do(rawtext, nil, TKMLGQMap)
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
			ckey, ok := tkmlgqContactKeyMap[lckey]
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
