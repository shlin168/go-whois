package domain

import (
	"sort"
	"strings"
)

type EUParser struct{}

type EUTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewEUTLDParser() *EUTLDParser {
	return &EUTLDParser{
		parser: NewParser(),
	}
}

func (euw *EUTLDParser) GetName() string {
	return "eu"
}

func (euw *EUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")
	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	for idx, line := range lines {
		key, val, _ := getKeyValFromLine(line)
		switch key {
		case "Domain":
			parsedWhois.DomainName = val
		case "Registrar":
			contactFlg = REGISTRAR
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
		case "Technical":
			contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
		case "Name servers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				if nss := strings.Split(ns, " "); len(nss) > 1 {
					// sometimes ns contains ip. E.g., ns1.onlinecasinos24.eu (217.182.6.84)
					ns = nss[0]
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "Name", "Organization", "Organisation", "Email", "Address", "Website":
			if len(contactFlg) == 0 {
				continue
			}
			if contactFlg == REGISTRAR {
				switch key {
				case "Name":
					parsedWhois.Registrar.Name = val
				case "Website":
					parsedWhois.Registrar.URL = val
				}
				continue
			}
			if contactFlg == TECH {
				switch key {
				case "Organization", "Organisation":
					contactsMap[TECH]["organization"] = val
				case "Email":
					contactsMap[TECH]["email"] = val
				}
			}
		}
	}
	sort.Strings(parsedWhois.NameServers)
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
