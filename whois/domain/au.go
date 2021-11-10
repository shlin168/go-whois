package domain

var AUMap map[string]string = map[string]string{
	"Registrant Contact Name": "c/registrant/name",
	"Registrant":              "c/registrant/organization",
	"Tech Contact Name":       "c/tech/name",
}

type AUParser struct{}

type AUTLDParser struct {
	parser IParser
}

func NewAUTLDParser() *AUTLDParser {
	return &AUTLDParser{
		parser: NewParser(),
	}
}

func (auw *AUTLDParser) GetName() string {
	return "au"
}

func (auw *AUTLDParser) GetParsedWhois(rawtext string) (*ParsedWhois, error) {
	parsedWhois, err := auw.parser.Do(rawtext, nil, AUMap)
	if err != nil {
		return nil, err
	}
	return parsedWhois, nil
}
