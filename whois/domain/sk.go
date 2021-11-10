package domain

import (
	"strings"
)

var SKMap map[string]string = map[string]string{
	"EPP Status":    "statuses",
	"Email":         "reg/abuse_contact_email",
	"Phone":         "reg/abuse_contact_phone",
	"Registrant":    "c/registrant/id",
	"Admin Contact": "c/admin/id",
	"Tech Contact":  "c/tech/id",
}

func skMapContactKeyValue(key string) string {
	if key == "Country Code" {
		return "country"
	}
	if key == "State/Province" {
		return "state"
	}
	return strings.ToLower(key)
}

type SKTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (skw *SKTLDParser) GetName() string {
	return "sk"
}

func NewSKTLDParser() *SKTLDParser {
	return &SKTLDParser{
		parser:   NewParser(),
		stopFunc: nil,
	}
}

func (skw *SKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := skw.parser.Do(rawtext, skw.stopFunc, SKMap)
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
		case "Registrar":
			if key, val, err := getKeyValFromLine(lines[idx+1]); err == nil && key == "Name" {
				parsedWhois.Registrar.Name = val
			}
		case "Contact":
			switch val {
			case parsedWhois.Contacts.Registrant.ID:
				contactFlg = REGISTRANT
				contactsMap[REGISTRANT] = make(map[string]interface{})
			case parsedWhois.Contacts.Admin.ID:
				contactFlg = ADMIN
				contactsMap[ADMIN] = make(map[string]interface{})
			case parsedWhois.Contacts.Tech.ID:
				contactFlg = TECH
				contactsMap[TECH] = make(map[string]interface{})
			}
		case "Name", "Organization", "Phone", "Email", "Street",
			"City", "Postal Code", "Country Code", "State/Province":
			if len(contactFlg) == 0 {
				continue
			}
			ckey := skMapContactKeyValue(key)
			if key == "Street" {
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
	return parsedWhois, err
}
