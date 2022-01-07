package whois

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// WhoisServerListURL maps tlds to corresponding whois server list
const WhoisServerListURL = "http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml"

// DomainList is generated by https://www.onlinetool.io/xmltogo/
// parse xml URL: // ref. http://whois-server-list.github.io/whois-server-list/3.0/whois-server-list.xml
type DomainList struct {
	XMLName     xml.Name `xml:"domainList"`
	Text        string   `xml:",chardata"`
	Version     string   `xml:"version,attr"`
	Date        string   `xml:"date"`
	Description string   `xml:"description"`
	Domain      []struct {
		Text                string `xml:",chardata"`
		Name                string `xml:"name,attr"`
		Source              string `xml:"source"`
		Created             string `xml:"created"`
		Changed             string `xml:"changed"`
		RegistrationService string `xml:"registrationService"`
		State               string `xml:"state"`
		WhoisServer         []struct {
			Text             string `xml:",chardata"`
			Host             string `xml:"host,attr"`
			Source           string `xml:"source"`
			AvailablePattern string `xml:"availablePattern"`
			ErrorPattern     string `xml:"errorPattern"`
			QueryFormat      string `xml:"queryFormat"`
		} `xml:"whoisServer"`
		CountryCode string `xml:"countryCode"`
		Domain      []struct {
			Text        string `xml:",chardata"`
			Name        string `xml:"name,attr"`
			Source      string `xml:"source"`
			WhoisServer []struct {
				Text             string `xml:",chardata"`
				Host             string `xml:"host,attr"`
				Source           string `xml:"source"`
				AvailablePattern string `xml:"availablePattern"`
				ErrorPattern     string `xml:"errorPattern"`
				QueryFormat      string `xml:"queryFormat"`
			} `xml:"whoisServer"`
		} `xml:"domain"`
	} `xml:"domain"`
}

type WhoisServer struct {
	Host     string
	AvailPtn *regexp.Regexp // pattern to check if domain is available
}

// DomainWhoisServerMap stores tld and it's whois server list
// key: tld
// val: list of whoisServer
type DomainWhoisServerMap map[string][]WhoisServer

// NewDomainWhoisServerMap initialize map from 'xmlpath' support local file path and file from web
func NewDomainWhoisServerMap(xmlpath string) (DomainWhoisServerMap, error) {
	var content []byte
	if strings.HasPrefix(xmlpath, "http") {
		resp, err := http.Get(xmlpath)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("unexpected server resp code: %d", resp.StatusCode)
		}
		if content, err = ioutil.ReadAll(resp.Body); err != nil {
			return nil, err
		}
	} else {
		domainXML, err := os.Open(xmlpath)
		if err != nil {
			return nil, err
		}
		defer domainXML.Close()
		if content, _ = ioutil.ReadAll(domainXML); err != nil {
			return nil, err
		}
	}
	dls := DomainList{}
	if err := xml.Unmarshal(content, &dls); err != nil {
		return nil, err
	}
	DomainWhoisServerMap := make(map[string][]WhoisServer)
	for _, domain := range dls.Domain {
		if len(domain.WhoisServer) > 0 {
			DomainWhoisServerMap[domain.Name] = make([]WhoisServer, len(domain.WhoisServer))
			for i, ws := range domain.WhoisServer {
				DomainWhoisServerMap[domain.Name][i].Host = ws.Host
				if len(ws.AvailablePattern) > 0 {
					ptn, err := regexp.Compile(ws.AvailablePattern)
					if err == nil {
						DomainWhoisServerMap[domain.Name][i].AvailPtn = ptn
					}
				}
			}
		}
		// contains subdomains
		for _, sd := range domain.Domain {
			if len(sd.WhoisServer) > 0 {
				DomainWhoisServerMap[sd.Name] = make([]WhoisServer, len(sd.WhoisServer))
				for i, sws := range sd.WhoisServer {
					DomainWhoisServerMap[sd.Name][i].Host = sws.Host
					if len(sws.AvailablePattern) > 0 {
						ptn, err := regexp.Compile(sws.AvailablePattern)
						if err == nil {
							DomainWhoisServerMap[sd.Name][i].AvailPtn = ptn
						}
					}
				}
			}
		}
	}
	// for those domains that only subdomains contains whois server
	DomainWhoisServerMap["mc"] = []WhoisServer{{Host: "whois.ripe.net"}}
	ptn, err := regexp.Compile("\\Qno entries found\\E")
	if err == nil {
		DomainWhoisServerMap["mc"][0].AvailPtn = ptn
	}
	DomainWhoisServerMap["mm"] = []WhoisServer{{Host: "whois.nic.mm"}}
	ptn, err = regexp.Compile("\\QNo domains matched\\E")
	if err == nil {
		DomainWhoisServerMap["mc"][0].AvailPtn = ptn
	}
	// wrong or unavailable first whois server in whois-server-list.xml
	// ai: whois.ai -> whois.nic.ai
	DomainWhoisServerMap["ai"] = []WhoisServer{{Host: "whois.nic.ai"}}
	// cyou: whois.afilias-srs.net -> whois.nic.cyou
	DomainWhoisServerMap["cyou"] = []WhoisServer{{Host: "whois.nic.cyou"}}
	// live: whois.rightside.co -> whois.nic.live
	DomainWhoisServerMap["live"] = []WhoisServer{{Host: "whois.nic.live"}}
	// vg: ccwhois.ksregistry.net -> whois.nic.vg
	DomainWhoisServerMap["vg"] = []WhoisServer{{Host: "whois.nic.vg"}}
	// live: whois-dub.mm-registry.com -> whois.nic.live
	DomainWhoisServerMap["surf"] = []WhoisServer{{Host: "whois.nic.surf"}}

	// Not available server
	// in: whois.inregistry.in -> whois.registry.in
	// pt: whois.dns.pt -> whois.ripe.net (while seems that this server return 'no entries found' for every domain?)
	DomainWhoisServerMap["pt"] = []WhoisServer{{Host: "whois.ripe.net"}}
	for k, v := range DomainWhoisServerMap {
		if len(v) > 0 && v[0].Host == "whois.inregistry.in" {
			DomainWhoisServerMap[k] = []WhoisServer{{Host: "whois.registry.in"}}
		}
		if len(v) > 0 && v[0].Host == "whois.dns.pt" {
			DomainWhoisServerMap[k] = []WhoisServer{{Host: "whois.ripe.net"}}
		}
	}

	// unfilled whois server
	for _, tld := range []string{"ar", "blogspot.com.ar", "com.ar", "edu.ar", "gob.ar",
		"gov.ar", "int.ar", "mil.ar", "net.ar", "org.ar", "tur.ar"} {
		DomainWhoisServerMap[tld] = []WhoisServer{{Host: "whois.nic.ar"}}
	}

	return DomainWhoisServerMap, nil
}

// GetWhoisServer get whois server list given public suffix
// Example:
//		ps="pooch.co.uk", search order: "pooch.co.uk" -> "co.uk" -> "uk"
//		ps="co.uk", 	  search order: "co.uk" -> "uk"
func (dsmap DomainWhoisServerMap) GetWhoisServer(ps string) []WhoisServer {
	var wss []WhoisServer
	lvl := strings.Split(ps, ".")
	for i := 1; i <= len(lvl); i++ {
		tlds := strings.SplitN(ps, ".", i)
		if ws, ok := dsmap[tlds[len(tlds)-1]]; ok {
			return ws
		}
	}
	return wss
}
