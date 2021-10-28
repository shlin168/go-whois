package domain

import (
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

var FRMap map[string]string = map[string]string{
	"holder-c": "c/registrant/id",
	"admin-c":  "c/admin/id",
	"tech-c":   "c/tech/id",
}

var frContactKeyMap = map[string]string{
	"e-mail":  "email",
	"address": "street",
	"fax-no":  "fax",
	"contact": "name",
}

type FRParser struct{}

type FRTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewFRTLDParser() *FRTLDParser {
	return &FRTLDParser{
		parser: NewParser(),
	}
}

func (frw *FRTLDParser) GetName() string {
	return "fr"
}

func (frw *FRTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := frw.parser.Do(rawtext, nil, FRMap)
	if err != nil {
		return nil, err
	}

	var createDone, updateDone, expireDone, holdercDone, admincDone, techcDone bool
	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "created":
			if !createDone {
				parsedWhois.CreatedDateRaw = val
				parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(val, WhoisTimeFmt)
				createDone = true
			}
		case "last-update":
			if !updateDone {
				parsedWhois.UpdatedDateRaw = val
				parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
				updateDone = true
			}
		case "Expiry Date":
			if !expireDone {
				parsedWhois.ExpiredDateRaw = val
				parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
				expireDone = true
			}
		case "holder-c":
			if !holdercDone && parsedWhois.Contacts != nil && parsedWhois.Contacts.Registrant != nil {
				parsedWhois.Contacts.Registrant.ID = val
				holdercDone = true
			}
		case "admin-c":
			if !admincDone && parsedWhois.Contacts != nil && parsedWhois.Contacts.Admin != nil {
				parsedWhois.Contacts.Admin.ID = val
				admincDone = true
			}
		case "tech-c":
			if !techcDone && parsedWhois.Contacts != nil && parsedWhois.Contacts.Tech != nil {
				parsedWhois.Contacts.Tech.ID = val
				techcDone = true
			}
		case "registrar":
			if parsedWhois.Registrar != nil && val == parsedWhois.Registrar.Name {
				contactFlg = REGISTRAR
			}
		case "nic-hdl":
			if parsedWhois.Contacts == nil {
				continue
			}
			if parsedWhois.Contacts.Registrant != nil && val == parsedWhois.Contacts.Registrant.ID && contactsMap[REGISTRANT] == nil {
				contactFlg = REGISTRANT
				contactsMap[REGISTRANT] = make(map[string]interface{})
				contactsMap[REGISTRANT]["id"] = val
				continue
			}
			if parsedWhois.Contacts.Admin != nil && val == parsedWhois.Contacts.Admin.ID && contactsMap[ADMIN] == nil {
				contactFlg = ADMIN
				contactsMap[ADMIN] = make(map[string]interface{})
				contactsMap[ADMIN]["id"] = val
				continue
			}
			if parsedWhois.Contacts.Tech != nil && val == parsedWhois.Contacts.Tech.ID && contactsMap[TECH] == nil {
				contactFlg = TECH
				contactsMap[TECH] = make(map[string]interface{})
				contactsMap[TECH]["id"] = val
			}
		case "address", "country", "phone", "fax-no", "e-mail", "website", "contact":
			if len(contactFlg) == 0 {
				continue
			}
			if contactFlg == REGISTRAR {
				switch key {
				case "e-mail":
					parsedWhois.Registrar.AbuseContactEmail = val
				case "phone":
					parsedWhois.Registrar.AbuseContactPhone = val
				case "website":
					parsedWhois.Registrar.URL = val
				}
				continue
			}
			ckey, ok := frContactKeyMap[key]
			if !ok {
				ckey = key
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
	return parsedWhois, nil
}
