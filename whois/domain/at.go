package domain

import (
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const (
	ATTimeFmt = "20060102 15:04:05"
)

var ATMap map[string]string = map[string]string{
	"registrant": "c/registrant/id",
	"tech-c":     "c/tech/id",
}

var atContactKeyMap = map[string]string{
	"personname":     "name",
	"e-mail":         "email",
	"street address": "street",
	"postal code":    "postal",
	"fax-no":         "fax",
}

type ATTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func (atw *ATTLDParser) GetName() string {
	return "at"
}

func NewATTLDParser() *ATTLDParser {
	return &ATTLDParser{
		parser: NewParser(),
	}
}

func (atw *ATTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := atw.parser.Do(rawtext, nil, ATMap)
	if err != nil {
		return nil, err
	}

	contactsMap := map[string]map[string]interface{}{}
	var tmpContact map[string]interface{}
	var updateFlg bool
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "registrar":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = val
		case "changed":
			if !updateFlg {
				parsedWhois.UpdatedDateRaw = val
				updateFlg = true
			}
		case "tech-c", "registrant":
			if val == "<data not disclosed>" {
				continue
			}
			switch key {
			case "tech-c":
				parsedWhois.Contacts.Tech.ID = val
			case "registrant":
				parsedWhois.Contacts.Registrant.ID = val
			}
		case "nic-hdl":
			if val == parsedWhois.Contacts.Registrant.ID {
				contactsMap[REGISTRANT] = tmpContact
			}
			if val == parsedWhois.Contacts.Tech.ID {
				contactsMap[TECH] = tmpContact
			}
		case "personname", "organization", "street address", "postal code", "city",
			"country", "phone", "e-mail", "fax-no":
			if key == "personname" {
				tmpContact = make(map[string]interface{})
			}
			ckey := mapContactKeys(atContactKeyMap, key)
			if ckey == "street" {
				if _, ok := tmpContact[ckey]; !ok {
					tmpContact[ckey] = []string{}
				}
				tmpContact[ckey] = append(tmpContact[ckey].([]string), val)
				continue
			}
			tmpContact[ckey] = val
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	// Parsed Time again since it has a weird format
	parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(parsedWhois.UpdatedDateRaw, ATTimeFmt, WhoisTimeFmt)
	return parsedWhois, err
}
