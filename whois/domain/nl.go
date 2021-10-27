package domain

import (
	"net/mail"
	"sort"
	"strings"
)

type NLParser struct{}

type NLTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewNLTLDParser() *NLTLDParser {
	return &NLTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "Copyright notice") },
	}
}

func (nlw *NLTLDParser) GetName() string {
	return "nl"
}

func (nlw *NLTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := nlw.parser.Do(rawtext, nlw.stopFunc)
	if err != nil {
		return nil, err
	}

	// Parse for specific fields after default parser
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if nlw.stopFunc(line) {
			break
		}
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "Registrar":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
		case "Abuse Contact":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			for i := 1; i < 3; i++ {
				val := strings.TrimSpace(lines[idx+i])
				if len(val) == 0 {
					break
				}
				if _, err := mail.ParseAddress(val); err == nil {
					parsedWhois.Registrar.AbuseContactEmail = val
				} else {
					parsedWhois.Registrar.AbuseContactPhone = val
				}
			}

		case "Domain nameservers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		}
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
