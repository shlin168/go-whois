package domain

import "strings"

var FRMap map[string]string = map[string]string{
	"created":     "created_date",
	"last-update": "updated_date",
	"Expiry Date": "expired_date",
	"registrar":   "reg/name",
}

type FRParser struct{}

type FRTLDParser struct {
	parser IParser
}

func NewFRTLDParser() *FRTLDParser {
	return &FRTLDParser{
		parser: NewNicHdlParser(map[string]string{
			"e-mail":  "email",
			"address": "street",
			"fax-no":  "fax",
			"contact": "name",
			"country": "country",
			"phone":   "phone",
		}),
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

	var registrarFlg bool
	if parsedWhois.Registrar != nil {
		lines := strings.Split(rawtext, "\n")
		for idx, line := range lines {
			if IsCommentLine(line) {
				continue
			}
			key, val, _ := getKeyValFromLine(line)
			if len(key) == 0 {
				registrarFlg = false
			}
			if key == "registrar" && len(strings.TrimSpace(lines[idx-1])) == 0 {
				registrarFlg = true
				continue
			}

			if registrarFlg {
				switch key {
				case "e-mail":
					parsedWhois.Registrar.AbuseContactEmail = val
				case "phone":
					parsedWhois.Registrar.AbuseContactPhone = val
				case "website":
					parsedWhois.Registrar.URL = val
				}
			}
		}
	}
	return parsedWhois, nil
}
