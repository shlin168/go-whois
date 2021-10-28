package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const (
	plTimeFmt = "2006.01.02 15:04:05"
)

type PLParser struct{}

type PLTLDParser struct {
	parser IParser
}

func NewPLTLDParser() *PLTLDParser {
	return &PLTLDParser{
		parser: NewParser(),
	}
}

func (plw *PLTLDParser) GetName() string {
	return "pl"
}

func (plw *PLTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := plw.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var nsFlg, regFlg bool
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		key, val, err := getKeyValFromLine(line)
		switch key {
		case "created":
			parsedWhois.CreatedDateRaw = val
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		case "last modified":
			parsedWhois.UpdatedDateRaw = val
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		case "renewal date":
			parsedWhois.ExpiredDateRaw = val
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(val, plTimeFmt, WhoisTimeFmt)
		case "REGISTRAR":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
			regFlg = true
		case "nameservers":
			nsFlg = true
		case "Telephone":
			if regFlg {
				parsedWhois.Registrar.AbuseContactPhone = val
			}
		case "Email":
			if regFlg {
				parsedWhois.Registrar.AbuseContactEmail = val
			}
		default:
			if nsFlg && len(key) > 0 && err != nil && len(parsedWhois.NameServers) > 0 {
				ns := strings.Split(key, " ")[0]
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			} else {
				nsFlg = false
			}
		}
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
