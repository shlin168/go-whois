package domain

var RUMap map[string]string = map[string]string{
	"admin-contact": "reg/url",
	"state":         "statuses",
	"org":           "c/registrant/organization",
}

type RUParser struct{}

type RUTLDParser struct {
	parser IParser
}

func NewRUTLDParser() *RUTLDParser {
	return &RUTLDParser{
		parser: NewParser(),
	}
}

func (ruw *RUTLDParser) GetName() string {
	return "ru"
}

func (ruw *RUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := ruw.parser.Do(rawtext, nil, RUMap)
	if err != nil {
		return nil, err
	}
	return parsedWhois, nil
}
