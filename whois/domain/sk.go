package domain

import (
	"encoding/json"
	"sort"
	"strings"
)

var SKMap map[string]string = map[string]string{
	"Email":         "reg/abuse_contact_email",
	"Phone":         "reg/abuse_contact_phone",
	"Registrant":    "c/registrant/id",
	"Admin Contact": "c/admin/id",
	"Tech Contact":  "c/tech/id",
}

func mapContactKeyValue(key string) string {
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

func (wb *SKTLDParser) GetName() string {
	return "sk"
}

func NewSKTLDParser() *SKTLDParser {
	return &SKTLDParser{
		parser:   NewParser(),
		stopFunc: nil,
	}
}

func (skw *SKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	w, err := skw.parser.Do(rawtext, skw.stopFunc, SKMap)
	if err != nil {
		return nil, err
	}
	// Parse for specific fields after default parser
	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "EPP Status":
			for _, status := range strings.Split(val, ",") {
				w.Statuses = append(w.Statuses, strings.TrimSpace(status))
			}
			sort.Strings(w.Statuses)
		case "Registrar":
			if key, val, err := getKeyValFromLine(lines[idx+1]); err == nil && key == "Name" {
				w.Registrar.Name = val
			}
		case "Contact":
			if val == w.Contacts.Registrant.ID {
				contactFlg = REGISTRANT
				contactsMap[REGISTRANT] = make(map[string]interface{})
			} else if val == w.Contacts.Admin.ID {
				contactFlg = ADMIN
				contactsMap[ADMIN] = make(map[string]interface{})
			} else if val == w.Contacts.Tech.ID {
				contactFlg = TECH
				contactsMap[TECH] = make(map[string]interface{})
			}
		case "Name", "Organization", "Phone", "Email", "Street",
			"City", "Postal Code", "Country Code", "State/Province":
			if len(contactFlg) == 0 {
				continue
			}
			ckey := mapContactKeyValue(key)
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
		w.Contacts = contacts
	}
	return w, err
}

func map2ParsedContacts(cMap map[string]map[string]interface{}) (*Contacts, error) {
	// Marshal from map and unmarshal to Whois Struct
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
