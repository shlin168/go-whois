package domain

import (
	"sort"
	"strings"

	"github.com/shlin168/go-whois/whois/utils"
)

var ARMap map[string]string = map[string]string{
	"name": "c/registrant/name",
}

type ARParser struct{}

type ARTLDParser struct {
	parser   IParser
	stopFunc func(string) bool
}

func NewARTLDParser() *ARTLDParser {
	return &ARTLDParser{
		parser: NewParser(),
	}
}

func (arw *ARTLDParser) GetName() string {
	return "ar"
}

func (arw *ARTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := arw.parser.Do(rawtext, nil, ARMap)
	if err != nil {
		return nil, err
	}

	var createDone, updateDone, expireDone bool
	// var contactFlg string
	// contactsMap := map[string]map[string]interface{}{}
	lines := strings.Split(rawtext, "\n")
	for _, line := range lines {
		if IsCommentLine(line) {
			continue
		}
		key, val, err := getKeyValFromLine(line)
		if err != nil {
			continue
		}
		switch key {
		case "registered":
			if !createDone {
				parsedWhois.CreatedDateRaw = val
				parsedWhois.CreatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.CreatedDateRaw, WhoisTimeFmt)
				createDone = true
			}
		case "changed":
			if !updateDone {
				parsedWhois.UpdatedDateRaw = val
				parsedWhois.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.UpdatedDateRaw, WhoisTimeFmt)
				updateDone = true
			}
		case "expire":
			if !expireDone {
				parsedWhois.ExpiredDateRaw = val
				parsedWhois.ExpiredDate, _ = utils.GuessTimeFmtAndConvert(parsedWhois.ExpiredDateRaw, WhoisTimeFmt)
				expireDone = true
			}
		}
	}
	for i := 0; i < len(parsedWhois.NameServers); i++ {
		parsedWhois.NameServers[i] = strings.Split(parsedWhois.NameServers[i], " ")[0]
	}
	sort.Strings(parsedWhois.NameServers)
	return parsedWhois, nil
}
