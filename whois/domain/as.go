package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const asTfmt = "02 January 2006 15:04:05"

type ASParser struct{}

type ASTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewASTLDParser() *ASTLDParser {
	return &ASTLDParser{
		parser:   NewParser(),
		stopFunc: func(line string) bool { return strings.HasPrefix(line, "WHOIS lookup made on") },
	}
}

func (asw *ASTLDParser) GetName() string {
	return "as"
}

func (asw *ASTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois := &ParsedWhois{}
	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		if asw.stopFunc(line) {
			break
		}
		line = strings.TrimSpace(line)
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "Domain":
			parsedWhois.DomainName = strings.TrimSpace(lines[idx+1])
		case "Registrar":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
		case "Name servers":
			for i := 1; i <= 20; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
			sort.Strings(parsedWhois.NameServers)
		case "Domain Status":
			for i := 1; i <= 10; i++ {
				status := strings.TrimSpace(lines[idx+i])
				if len(status) == 0 {
					break
				}
				parsedWhois.Statuses = append(parsedWhois.Statuses, status)
			}
		case "Relevant dates":
			parsedWhois.CreatedDateRaw = strings.TrimSpace(lines[idx+1])
			createdate := handleCreateDate(parsedWhois.CreatedDateRaw)
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(createdate, asTfmt, WhoisTimeFmt)
		}
	}
	return parsedWhois, nil
}

func handleCreateDate(ts string) string {
	// Registered on 06th December 2017 at 13:10:17.774 -> 06 Dec 2017 13:10:17
	cd := strings.TrimLeft(ts, "Registered on ")
	cd = strings.Replace(cd, " at ", " ", 1)
	cd = dayReplacer.Replace(cd)
	cd = strings.Split(cd, ".")[0]
	return cd
}
