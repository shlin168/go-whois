package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const fiTfmt = "2.1.2006 15:04:05"

var fiContactKeyMap = map[string]string{
	"holder":       "name",
	"holder email": "email",
	"address":      "street",
}

type FIParser struct{}

type FITLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewFITLDParser() *FITLDParser {
	return &FITLDParser{
		parser: NewParser(),
	}
}

func (fiw *FITLDParser) GetName() string {
	return "fi"
}

func (fiw FITLDParser) getKeyValFromLine(line string) (string, string) {
	kv := strings.Split(line, "..: ")
	if len(kv) == 2 {
		return strings.ReplaceAll(kv[0], ".", ""), kv[1]
	}
	return line, ""
}

func (fiw *FITLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := fiw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}
	var contactFlg string
	contactsMap := map[string]map[string]interface{}{}
	var regContact, techContact map[string]interface{}
	lines := strings.Split(strings.ReplaceAll(rawtext, "\r\n", "\n"), "\n")
	for _, line := range lines {
		key, val := fiw.getKeyValFromLine(line)
		if len(key) == 0 {
			continue
		}
		switch key {
		case "domain":
			parsedWhois.DomainName = val
		case "status":
			parsedWhois.Statuses = []string{val}
		case "created":
			parsedWhois.CreatedDateRaw = val
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(parsedWhois.CreatedDateRaw, fiTfmt, WhoisTimeFmt)
		case "expires":
			parsedWhois.ExpiredDateRaw = val
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(parsedWhois.ExpiredDateRaw, fiTfmt, WhoisTimeFmt)
		case "modified":
			parsedWhois.UpdatedDateRaw = val
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(parsedWhois.UpdatedDateRaw, fiTfmt, WhoisTimeFmt)
		case "nserver":
			if len(parsedWhois.NameServers) == 0 {
				parsedWhois.NameServers = []string{}
			}
			parsedWhois.NameServers = append(parsedWhois.NameServers, strings.Split(val, " ")[0])
		case "dnssec":
			parsedWhois.Dnssec = val
		case "Holder":
			contactFlg = REGISTRANT
			regContact = make(map[string]interface{})
		case "Tech":
			contactFlg = TECH
			techContact = make(map[string]interface{})
		case "name", "holder", "address", "city", "country", "phone", "holder email", "email", "postal":
			var tmpContact map[string]interface{}
			switch contactFlg {
			case REGISTRANT:
				tmpContact = regContact
			case TECH:
				tmpContact = techContact
			}
			if tmpContact != nil {
				ckey := mapContactKeys(fiContactKeyMap, key)
				if ckey == "street" {
					if _, ok := tmpContact[ckey]; !ok {
						tmpContact[ckey] = []string{}
					}
					tmpContact[ckey] = append(tmpContact[ckey].([]string), val)
					continue
				}
				tmpContact[ckey] = val
			}
		case "Registrar":
			parsedWhois.Registrar = &Registrar{}
		case "registrar":
			if parsedWhois.Registrar != nil {
				parsedWhois.Registrar.Name = val
			}
		case "www":
			if parsedWhois.Registrar != nil {
				parsedWhois.Registrar.URL = val
			}
		}
	}
	contactsMap[REGISTRANT] = regContact
	contactsMap[TECH] = techContact
	contacts, err := map2ParsedContacts(contactsMap)
	if err == nil {
		parsedWhois.Contacts = contacts
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
