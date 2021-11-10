package domain

import (
	"sort"
	"strings"
)

type BEParser struct{}

type BETLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewBETLDParser() *BETLDParser {
	return &BETLDParser{
		parser: NewParser(),
	}
}

func (bew *BETLDParser) GetName() string {
	return "be"
}

func (bew *BETLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := bew.parser.Do(rawtext, nil)
	if err != nil {
		return nil, err
	}

	var regFlg bool
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, _ := getKeyValFromLine(line)
		switch key {
		case "Status":
			parsedWhois.Statuses = []string{val}
		case "Registrar":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			regFlg = true
		case "Nameservers":
			parsedWhois.NameServers = []string{}
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "Flags":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.Statuses = append(parsedWhois.Statuses, ns)
			}
		case "Name":
			if regFlg {
				parsedWhois.Registrar.Name = val
			}
		case "Website":
			if regFlg {
				parsedWhois.Registrar.URL = val
			}
		case "Phone":
			if regFlg {
				parsedWhois.Registrar.AbuseContactPhone = val
			}
		}
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
