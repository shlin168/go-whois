package domain

import (
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

var IRMap map[string]string = map[string]string{
	"holder-c": "c/registrant/id",
	"admin-c":  "c/admin/id",
	"tech-c":   "c/tech/id",
	"bill-c":   "c/billing/id",
}

var irContactKeyMap = map[string]string{
	"org":     "organization",
	"e-mail":  "email",
	"address": "street",
	"fax-no":  "fax",
}

func mapIRContactKey(key string) string {
	if val, ok := irContactKeyMap[key]; ok {
		return val
	}
	return key
}

type IRParser struct{}

type IRTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewIRTLDParser() *IRTLDParser {
	return &IRTLDParser{
		parser: NewParser(),
	}
}

func (irw *IRTLDParser) GetName() string {
	return "ir"
}

func (irw *IRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := irw.parser.Do(rawtext, nil, IRMap)
	if err != nil {
		return nil, err
	}

	var updateDone, expireDone bool
	var currNicHdl string
	contactsMap := map[string]map[string]interface{}{}
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
		case "last-updated":
			if !updateDone {
				parsedWhois.UpdatedDateRaw = val
				parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
				updateDone = true
			}
		case "expire-date":
			if !expireDone {
				parsedWhois.ExpiredDateRaw = val
				parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
				expireDone = true
			}
		case "nic-hdl":
			if parsedWhois.Contacts != nil {
				currNicHdl = val
				if parsedWhois.Contacts.Registrant != nil && val == parsedWhois.Contacts.Registrant.ID {
					contactsMap[REGISTRANT] = make(map[string]interface{})
					contactsMap[REGISTRANT]["id"] = val
				}
				if parsedWhois.Contacts.Admin != nil && val == parsedWhois.Contacts.Admin.ID {
					contactsMap[ADMIN] = make(map[string]interface{})
					contactsMap[ADMIN]["id"] = val
				}
				if parsedWhois.Contacts.Tech != nil && val == parsedWhois.Contacts.Tech.ID {
					contactsMap[TECH] = make(map[string]interface{})
					contactsMap[TECH]["id"] = val
				}
				if parsedWhois.Contacts.Billing != nil && val == parsedWhois.Contacts.Billing.ID {
					contactsMap[BILLING] = make(map[string]interface{})
					contactsMap[BILLING]["id"] = val
				}
			}
		case "org", "address", "country", "phone", "fax-no", "e-mail", "website", "contact":
			if len(currNicHdl) == 0 {
				continue
			}
			ckey := mapIRContactKey(key)
			for _, c := range []string{REGISTRANT, ADMIN, TECH, BILLING} {
				if _, exist := contactsMap[c]; !exist {
					continue
				}
				if ckey == "street" {
					if _, ok := contactsMap[c][ckey]; !ok {
						contactsMap[c][ckey] = []string{}
					}
					contactsMap[c][ckey] = append(contactsMap[c][ckey].([]string), val)
					continue
				}
				contactsMap[c][ckey] = val
			}
		}
	}
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	return parsedWhois, nil
}
