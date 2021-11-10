package domain

import (
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const (
	CZTimeFmt1 = "02.01.2006 15:04:05"
	CZTimeFmt2 = "02.01.2006"
)

var CZMap map[string]string = map[string]string{
	"Registrant": "c/registrant/id",
	"registered": "created_date",
	"registrant": "c/registrant/id",
	"tech-c":     "c/tech/id",
}

type CZTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (czw *CZTLDParser) GetName() string {
	return "cz"
}

func NewCZTLDParser() *CZTLDParser {
	return &CZTLDParser{
		parser: NewParser(),
	}
}

func (czw *CZTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := czw.parser.Do(rawtext, nil, CZMap)
	if err != nil {
		return nil, err
	}

	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	var createFlg, updateFlg, expireFlg, regFlg bool
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			contactFlg = ""
			continue
		}
		switch key {
		case "registered":
			if !createFlg {
				parsedWhois.CreatedDateRaw = val
				createFlg = true
			}
		case "changed":
			if !updateFlg {
				parsedWhois.UpdatedDateRaw = val
				updateFlg = true
			}
		case "expire":
			if !expireFlg {
				parsedWhois.ExpiredDateRaw = val
				expireFlg = true
			}
		case "contact":
			// registrar
			if parsedWhois.Registrar != nil && "REG-"+val == parsedWhois.Registrar.Name {
				regFlg = true
			}
			// contacts: registrant/tech
			if parsedWhois.Contacts != nil {
				if parsedWhois.Contacts.Registrant != nil && val == parsedWhois.Contacts.Registrant.ID {
					contactFlg = REGISTRANT
					contactsMap[REGISTRANT] = make(map[string]interface{})
				} else if parsedWhois.Contacts.Tech != nil && val == parsedWhois.Contacts.Tech.ID {
					contactFlg = TECH
					contactsMap[TECH] = make(map[string]interface{})
				}
			}
		case "name", "org", "address":
			if len(contactFlg) == 0 {
				continue
			}
			if regFlg && key == "name" {
				parsedWhois.Registrar.Name = val
				continue
			}
			ckey := key
			if key == "address" {
				ckey = "street"
				if _, ok := contactsMap[contactFlg][ckey]; !ok {
					contactsMap[contactFlg][ckey] = []string{}
				}
				contactsMap[contactFlg][ckey] = append(contactsMap[contactFlg][ckey].([]string), val)
				continue
			}
			if key == "org" {
				ckey = "organization"
			}
			contactsMap[contactFlg][ckey] = val
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	// Name servers might contains ips
	// E.g., "beta.ns.active24.cz (81.0.238.27, 2001:1528:151::12)"
	for i := 0; i < len(parsedWhois.NameServers); i++ {
		if nss := strings.Split(parsedWhois.NameServers[i], " "); len(nss) > 1 {
			parsedWhois.NameServers[i] = nss[0]
		}
	}
	// Parsed Time again since it has a weird format
	parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(parsedWhois.CreatedDateRaw, CZTimeFmt1, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(parsedWhois.UpdatedDateRaw, CZTimeFmt1, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(parsedWhois.ExpiredDateRaw, CZTimeFmt2, WhoisTimeFmt)
	return parsedWhois, err
}
