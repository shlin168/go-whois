package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

const (
	tFmt = "Monday 2 Jan 2006"
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

func (ukw *UKTLDParser) GetName() string {
	return "uk"
}

func (ukw *UKTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := ukw.parser.Do(rawtext, ukw.stopFunc, UKMap)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(rawtext, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if ukw.stopFunc(line) {
			break
		}
		switch keyword := strings.TrimRight(line, ":"); keyword {
		case "Domain name", "Domain":
			parsedWhois.DomainName = strings.TrimSpace(lines[idx+1])
		case "Registrar", "Domain Owner":
			if parsedWhois.Registrar == nil {
				parsedWhois.Registrar = &Registrar{}
			}
			parsedWhois.Registrar.Name = strings.TrimSpace(lines[idx+1])
		case "Name servers", "Servers":
			for i := 1; i <= maxNServer; i++ {
				ns := strings.TrimSpace(lines[idx+i])
				if len(ns) == 0 {
					break
				}
				if end := strings.Index(ns, "\t"); end != -1 {
					// sometimes ns contains ip. E.g., ns0.cf.ac.uk\t131.251.133.10
					ns = ns[:end]
				}
				parsedWhois.NameServers = append(parsedWhois.NameServers, ns)
			}
		case "DNSSEC":
			parsedWhois.Dnssec = strings.TrimSpace(lines[idx+1])
		case "Entry created":
			parsedWhois.CreatedDateRaw = strings.TrimSpace(lines[idx+1])
			adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.CreatedDateRaw)
			parsedWhois.CreatedDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
		case "Entry updated":
			parsedWhois.UpdatedDateRaw = strings.TrimSpace(lines[idx+1])
			adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.UpdatedDateRaw)
			parsedWhois.UpdatedDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
		case "Renewal date":
			parsedWhois.ExpiredDateRaw = strings.TrimSpace(lines[idx+1])
			adjustDT := removeStRdNdThAndTrimMonInTime(parsedWhois.ExpiredDateRaw)
			parsedWhois.ExpiredDate, _ = utils.ConvTimeFmt(adjustDT, tFmt, WhoisTimeFmt)
		}
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}

func removeStRdNdThAndTrimMonInTime(t string) string {
	// Tuesday 1st Feb 2022 -> Tuesday 1 Feb 2022
	// Wednesday 13th October 2021 -> Wednesday 13 Oct 2021
	ts := strings.Split(t, " ")
	if len(ts) < 3 {
		return t
	}
	ts[1] = dayReplacer.Replace(ts[1])
	if len(ts[2]) > 3 {
		ts[2] = ts[2][:3]
	}
	return strings.Join(ts, " ")
}
