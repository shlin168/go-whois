package ip

import (
	"encoding/json"
	"strings"

	"github.com/sirupsen/logrus"

	wd "github.com/shlin168/go-whois/whois/domain"
	"github.com/shlin168/go-whois/whois/utils"
)

var DefaultIPKeyMap map[string]string = map[string]string{
	"inet6num": "inetnum",
	// type = net
	"NetName": "netname",
	// type = route
	"route":  "route/id",
	"route6": "route/id",
	"origin": "asn",
	// type = irt
	"mnt-irt": "mnt_irt",
	"irt":     "irt/id",
	// type = person, role
	"nic-hdl": "person+role/id",
	"person":  "name",
	"role":    "name",
	// type = organization
	"organization": "org/id",
	"org-name":     "name",
	// type = mntner
	"mntner": "mntner/id",
	// contact keys
	"admin-c":       "admin",
	"tech-c":        "tech",
	"mnt-by":        "mnt_by",
	"mnt-lower":     "mnt_lower",
	"mnt-routes":    "mnt_routes",
	"abuse-mailbox": "abuse_mailbox",
	"e-mail":        "email",
	"fax-no":        "fax",
	"irt-nfy":       "notified_email",
	"notify":        "notified_email",
	"last-modified": "updated_date",
	// whois.arin.net
	"NetRange":       "inetnum",
	"CIDR":           "range/cidr",
	"OriginAS":       "asn",
	"Comment":        "descr",
	"OrgId":          "org/id",
	"OrgName":        "name",
	"Updated":        "updated_date",
	"Address":        "address",
	"Country":        "country",
	"Ref":            "ref",
	"OrgTechHandle":  "org-tech/id",
	"OrgTechName":    "name",
	"OrgTechPhone":   "phone",
	"OrgTechEmail":   "email",
	"OrgTechRef":     "ref",
	"OrgAbuseHandle": "org-abuse/id",
	"OrgAbuseName":   "name",
	"OrgAbusePhone":  "phone",
	"OrgAbuseEmail":  "email",
	"OrgAbuseRef":    "ref",
	"OrgDNSHandle":   "org-dns/id",
	"OrgDNSName":     "name",
	"OrgDNSPhone":    "phone",
	"OrgDNSEmail":    "email",
	"OrgDNSRef":      "ref",
	// whois.lacnic.net
	"owner":      "org",
	"aut-num":    "asn",
	"inetnum-up": "parent",
}

var notFoundMsg = []string{
	"no data found",
	"not found",
	"no match",
	"not registered",
	"no object found",
	"object does not exist",
	"nothing found",
	"no entries found",
	"but this server does not have", // whois.iana.org
}

// IParser is used to parse whois information when input is ip
type IParser interface {
	Do(string, ...map[string]string) (*ParsedWhois, error)
}

type Parser struct {
	ip     string
	logger logrus.FieldLogger
}

func NewParser(ip string, logger logrus.FieldLogger) *Parser {
	return &Parser{ip: ip, logger: logger}
}

func (wp *Parser) Do(rawtext string, specKeyMaps ...map[string]string) (*ParsedWhois, error) {
	var ns []Network
	var cs []Contact
	var rs []Route
	var nmap map[string]interface{}
	block := false
	for _, line := range strings.Split(rawtext, "\n") {
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) == 0 {
			if nmap != nil {
				if _, ok := nmap["inetnum"]; ok {
					// Networks
					ipn, err := map2ParsedNetwork(nmap)
					if err != nil {
						wp.logger.WithField("ip", wp.ip).WithError(err).Warn("convert map to Network")
					}
					ipn.convDate()
					ns = append(ns, *ipn)
				} else if val, ok := nmap["type"]; ok && val == "route" {
					// Routes
					ipr, err := map2ParsedRoute(nmap)
					if err != nil {
						wp.logger.WithField("ip", wp.ip).WithError(err).Warn("convert map to Route")
					}
					ipr.convDate()
					ipr.Route = ipr.ID
					rs = append(rs, *ipr)
				} else {
					// Contacts
					ipc, err := map2ParsedContactIP(nmap)
					if err != nil {
						wp.logger.WithField("ip", wp.ip).WithError(err).Warn("convert map to Contact")
					}
					ipc.convDate()
					cs = append(cs, *ipc)
				}
				nmap = nil
			}
			block = false
			continue
		}
		if kv := strings.SplitN(line, ":", 2); len(kv) == 2 {
			if !block {
				nmap = make(map[string]interface{})
				block = true
			}
			if block {
				val := strings.TrimSpace(kv[1])
				key, ok := DefaultIPKeyMap[kv[0]]
				if !ok {
					key = kv[0]
				}
				if strings.HasSuffix(key, "/id") {
					if !strings.Contains(key, "+") {
						nmap["type"] = key[:strings.Index(key, "/")]
					}
					nmap["id"] = val
					continue
				}
				switch key {
				case "descr", "remarks", "address", "phone", "fax",
					"email", "admin", "tech", "notified_email", "abuse_mailbox",
					"mnt_by", "ref", "auth":
					if _, ok := nmap[key]; !ok {
						nmap[key] = []string{}
					}
					nmap[key] = append(nmap[key].([]string), val)
				case "inetnum":
					nmap[key] = val
					if fromAndTo := strings.Split(val, "-"); len(fromAndTo) == 2 {
						nmap["range"] = map[string]interface{}{
							"from": strings.TrimSpace(fromAndTo[0]),
							"to":   strings.TrimSpace(fromAndTo[1]),
						}
					} else if strings.Contains(val, "/") {
						nmap["range"] = map[string]interface{}{
							"cidr": []string{val},
						}
					}
				case "range/cidr":
					var cidrs []string
					for _, cidr := range strings.Split(val, ",") {
						cidrs = append(cidrs, strings.TrimSpace(cidr))
					}
					nmap["range"].(map[string]interface{})["cidr"] = cidrs
				case "name":
					switch kv[0] {
					case "person", "role":
						nmap["type"] = kv[0]
					}
					nmap[key] = val
				case "changed":
					// represents 'updated_date' in whois.lacnic.net
					if _, ok := nmap["updated_date"]; !ok {
						if _, err := utils.GuessTimeFmtAndConvert(val, wd.WhoisTimeFmt); err == nil {
							nmap["updated_date"] = val
						}
					}
				default:
					nmap[key] = val
				}
			}
		}
	}
	return &ParsedWhois{Networks: ns, Contacts: cs, Routes: rs}, nil
}

func map2ParsedNetwork(wMap map[string]interface{}) (*Network, error) {
	// Marshal from map and unmarshal to Whois Struct
	jsoncontent, err := json.Marshal(wMap)
	if err != nil {
		return nil, err
	}
	n := Network{}
	if err := json.Unmarshal(jsoncontent, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func map2ParsedRoute(wMap map[string]interface{}) (*Route, error) {
	// Marshal from map and unmarshal to Whois Struct
	jsoncontent, err := json.Marshal(wMap)
	if err != nil {
		return nil, err
	}
	r := Route{}
	if err := json.Unmarshal(jsoncontent, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func map2ParsedContactIP(wMap map[string]interface{}) (*Contact, error) {
	// Marshal from map and unmarshal to Whois Struct
	jsoncontent, err := json.Marshal(wMap)
	if err != nil {
		return nil, err
	}
	c := Contact{}
	if err := json.Unmarshal(jsoncontent, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// WhoisNotFound check keywords in rawtext
func WhoisNotFound(rawtext string) bool {
	rw := strings.ToLower(rawtext)
	for _, kw := range notFoundMsg {
		if strings.Index(rw, kw) != -1 {
			return true
		}
	}
	return false
}
