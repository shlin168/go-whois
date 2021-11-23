package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

var nicHdlDefaultMap map[string]string = map[string]string{
	"domain":   "domain",
	"nserver":  "name_servers",
	"status":   "statuses",
	"nic-hdl":  "nic-hdl",
	"holder-c": "c/registrant/id",
	"admin-c":  "c/admin/id",
	"tech-c":   "c/tech/id",
	"bill-c":   "c/billing/id",
}

// NicHdlParser implements parser for nic-hdl format rawtext
type NicHdlParser struct {
	keyMap        map[string]string
	contactKeyMap map[string]string
}

// NicHdlTLDParser implements nic-hdl parser which invoke Parser.Do with different parameters
type NicHdlTLDParser struct {
	parser IParser
}

func NewNicHdlParser(contactKeyMap map[string]string) *NicHdlParser {
	return &NicHdlParser{
		keyMap:        nicHdlDefaultMap,
		contactKeyMap: contactKeyMap,
	}
}

func NewNicHdlTLDParser() *NicHdlTLDParser {
	return &NicHdlTLDParser{
		parser: NewParser(),
	}
}

// GetName return name of TLDParser for logging
func (nhtld *NicHdlTLDParser) GetName() string {
	return "nic-hdl"
}

// GetParsedWhois invoke Do in parser to parse rawtext
func (nhtld *NicHdlTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	return nhtld.parser.Do(rawtext, nil)
}

// Do parse rawtext with DefaultKeyMap, stop parsing if stopFunc is given and return true
// If specKeyMaps is given, it will parse
func (nh *NicHdlParser) Do(rawtext string, stopFunc func(string) bool, specKeyMaps ...map[string]string) (*ParsedWhois, error) {
	// Initialize map to store whois information
	wMap := make(map[string]interface{})

	var currHdl string
	var hasParsedHdl map[string]bool
	var contactsMap map[string]map[string]interface{}

	if len(specKeyMaps) > 0 {
		for k, v := range specKeyMaps[0] {
			nh.keyMap[k] = v
		}
	}

	// Parsing raw text line by line
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if len(key) == 0 && len(currHdl) > 0 {
			if hasParsedHdl == nil {
				hasParsedHdl = make(map[string]bool)
			}
			hasParsedHdl[currHdl] = true
		}
		if err != nil {
			continue
		}
		if keyName, ok := nh.keyMap[key]; ok {
			// Registrar
			if strings.HasPrefix(keyName, "reg/") {
				if _, ok := wMap[REGISTRAR]; !ok {
					wMap[REGISTRAR] = make(map[string]string)
				}
				kn := strings.TrimLeft(keyName, "reg/")
				wMap[REGISTRAR].(map[string]string)[kn] = val
				if keyName == "reg/name" && len(strings.TrimSpace(lines[idx-1])) == 0 {
					currHdl = val
				}
				continue
			}
			// Contacts
			if strings.HasPrefix(keyName, "c/") {
				if contactsMap == nil {
					contactsMap = make(map[string]map[string]interface{})
				}
				switch keyName {
				case "c/registrant/id":
					if contactsMap[REGISTRANT] == nil {
						contactsMap[REGISTRANT] = map[string]interface{}{"id": val}
					}
				case "c/admin/id":
					if contactsMap[ADMIN] == nil {
						contactsMap[ADMIN] = map[string]interface{}{"id": val}
					}
				case "c/tech/id":
					if contactsMap[TECH] == nil {
						contactsMap[TECH] = map[string]interface{}{"id": val}
					}
				case "c/billing/id":
					if contactsMap[BILLING] == nil {
						contactsMap[BILLING] = map[string]interface{}{"id": val}
					}
				}
				continue
			}
			switch keyName {
			case "name_servers", "statuses":
				if _, ok := wMap[keyName]; !ok {
					wMap[keyName] = []string{}
				}
				wMap[keyName] = append(wMap[keyName].([]string), val)
			case "nic-hdl":
				if len(strings.TrimSpace(lines[idx-1])) == 0 {
					currHdl = val
				}
			default:
				// only fill if keyName not exist in whois map
				if _, ok := wMap[keyName]; !ok {
					wMap[keyName] = val
				}
			}
			continue
		}

		if ckey, ok := nh.contactKeyMap[key]; ok {
			if len(currHdl) == 0 {
				continue
			}
			if _, exist := hasParsedHdl[currHdl]; exist {
				continue
			}
			for _, c := range []string{REGISTRANT, ADMIN, TECH, BILLING} {
				if _, exist := contactsMap[c]; !exist {
					continue
				}
				if v, exist := contactsMap[c]["id"]; exist && v == currHdl {
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
	}
	wMap[CONTACTS] = contactsMap
	parsedWhois, err := map2ParsedWhois(wMap)
	if err != nil {
		return nil, err
	}

	// Since '...DateRaw' fields do not contains json struct tag, actual values are temporarily
	// stored in '...Date' fields. Manually copied them back and try to parse date fields
	parsedWhois.CreatedDateRaw = parsedWhois.CreatedDate
	parsedWhois.UpdatedDateRaw = parsedWhois.UpdatedDate
	parsedWhois.ExpiredDateRaw = parsedWhois.ExpiredDate
	parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
	parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
	parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)

	sort.Strings(parsedWhois.NameServers)
	sort.Strings(parsedWhois.Statuses)
	return parsedWhois, nil
}
