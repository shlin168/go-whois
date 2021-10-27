package domain

import (
	"strings"
)

var itContactKeyMap = map[string]string{
	"address": "street",
}

func itMapContactKeyValue(key string) string {
	if key == "Address" {
		return "street"
	}
	return strings.ToLower(key)
}

type ITTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (itw *ITTLDParser) GetName() string {
	return "it"
}

func NewITTLDParser() *ITTLDParser {
	return &ITTLDParser{
		parser: NewParser(),
	}
}

func (itw *ITTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := itw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	var addressFlg bool
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		key, val, err := getKeyValFromLine(line)
		switch key {
		case "Nameservers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "Registrar":
			contactFlg = REGISTRAR
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
		case "Registrant":
			contactFlg = REGISTRANT
			contactsMap[REGISTRANT] = make(map[string]interface{})
		case "Admin Contact":
			contactFlg = ADMIN
			contactsMap[ADMIN] = make(map[string]interface{})
		case "Technical Contacts":
			contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
		case "Name", "Organization", "Address", "":
			if len(contactFlg) == 0 {
				continue
			}
			if contactFlg == REGISTRAR {
				switch key {
				case "Name":
					parsedWhois.Registrar.Name = val
				case "Web":
					parsedWhois.Registrar.URL = val
				}
				continue
			}
			ckey := itMapContactKeyValue(key)
			if ckey == "street" {
				if _, ok := contactsMap[contactFlg][ckey]; !ok {
					contactsMap[contactFlg][ckey] = []string{}
				}
				contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
				addressFlg = true
				continue
			}
			contactsMap[contactFlg][ckey] = val
		default:
			if err != nil && addressFlg && len(contactFlg) > 0 && len(key) > 0 {
				contactsMap[contactFlg]["street"] = append(contactsMap[contactFlg]["street"].([]string), key)
			} else {
				addressFlg = false
			}
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
