package domain

import (
	"sort"
	"strings"
)

var UKMap = map[string]string{
	"URL": "reg/url",
}

type UKParser struct{}

type UKTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewUKTLDParser() *UKTLDParser {
	return &UKTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "--") },
	}
}

func (wb *UKTLDParser) GetName() string {
	return "uk"
}

func (uktld *UKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := uktld.parser.Do(rawtext, uktld.stopFunc, UKMap)
	if err != nil {
		return nil, err
	}

	// Parse for specific fields after default parser
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if uktld.stopFunc(line) {
			break
		}
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "Domain name":
			parsedWhois.DomainName = strings.TrimSpace(lines[idx+1])
		case "Registrar":
			parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
		case "Name servers":
			for i := 1; i <= 20; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "DNSSEC":
			parsedWhois.Dnssec = strings.TrimSpace(lines[idx+1])
		}
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
