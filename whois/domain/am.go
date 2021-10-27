package domain

import (
	"net/mail"
	"sort"
	"strings"
)

type AMParser struct{}

type AMTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewAMTLDParser() *AMTLDParser {
	return &AMTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "--") },
	}
}

func (amw *AMTLDParser) GetName() string {
	return "am"
}

func (amw *AMTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := amw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Status:") {
			if _, val, err := getKeyValFromLine(line); err == nil {
				parsedWhois.Statuses = []string{}
				for _, status := range strings.Split(val, ",") {
					parsedWhois.Statuses = append(parsedWhois.Statuses, strings.TrimSpace(status))
				}
				sort.Strings(parsedWhois.Statuses)
			}
		}
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "DNS servers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "Registrant":
			contactFlg = REGISTRANT
			contactsMap[REGISTRANT] = make(map[string]interface{})
			contactsMap[REGISTRANT]["name"] = strings.TrimSpace(lines[idx+1])
		case "Administrative contact":
			contactFlg = ADMIN
			contactsMap[ADMIN] = make(map[string]interface{})
			contactsMap[ADMIN]["name"] = strings.TrimSpace(lines[idx+2])
		case "Technical contact":
			contactFlg = TECH
			contactsMap[TECH] = make(map[string]interface{})
			contactsMap[TECH]["name"] = strings.TrimSpace(lines[idx+2])
		default:
			if len(keyword) == 0 {
				continue
			}
			if len(contactFlg) > 0 {
				if len(keyword) == 2 {
					contactsMap[contactFlg]["country"] = keyword
				}
				if _, err := mail.ParseAddress(keyword); err == nil {
					contactsMap[contactFlg]["email"] = keyword
				}
			}

		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
