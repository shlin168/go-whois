package ip

import (
	"github.com/shlin168/go-whois/whois/utils"

	wd "github.com/shlin168/go-whois/whois/domain"
)

/*
* ref.
* 	https://www.arin.net/resources/registry/whois/
*   https://www.lacnic.net/1040/2/lacnic/lacnics-whois
 */

type Whois struct {
	ParsedWhois *ParsedWhois `json:"parsed_whois"`
	WhoisServer string       `json:"whois_server,omitempty"` // whois server which response the rawtext, OrgId
	RawText     string       `json:"rawtext,omitempty"`
}

type ParsedWhois struct {
	Networks []Network `json:"networks,omitempty"`
	Contacts []Contact `json:"contacts,omitempty"`
	Routes   []Route   `json:"routes,omitempty"`
}

// Network records (NETs) define a range of IPv4 or IPv6 addresses
// and show the organizations and POCs with authority over them.
// To reposrt networtk abuse, contact mnt-irt
type Network struct {
	Inetnum  string `json:"inetnum,omitempty"`
	Range    *Range `json:"range,omitempty"`
	Org      string `json:"org,omitempty"`
	Netname  string `json:"netname,omitempty"`
	MntIrt   string `json:"mnt_irt,omitempty"`
	OriginAS string `json:"asn,omitempty"` // Origin As Network
	Parent   string `json:"parent,omitempty"`
	Contact
}

// Range parse result from Inetnum
type Range struct {
	From string   `json:"from,omitempty"`
	To   string   `json:"to,omitempty"`
	CIDR []string `json:"cidr,omitempty"`
}

type Route struct {
	OriginAS string `json:"asn,omitempty"`
	Route    string `json:"route,omitempty"`
	Contact
}

/* Contact store from all kinds of contact object, includes
* 	Person from https://www.apnic.net/manage-ip/using-whois/guide/person/
* 	Orgnization from https://www.apnic.net/manage-ip/using-whois/guide/organization/
*	Irt from https://www.apnic.net/manage-ip/using-whois/guide/irt/
*   ...
 */
type Contact struct {
	ID             string   `json:"id,omitempty"` // primary key
	Type           string   `json:"type,omitempty"`
	Name           string   `json:"name,omitempty"`
	Address        []string `json:"address,omitempty"`
	Country        string   `json:"country,omitempty"`
	Phone          []string `json:"phone,omitempty"`
	Fax            []string `json:"fax,omitempty"`
	Email          []string `json:"email,omitempty"`
	Description    []string `json:"descr,omitempty"`
	Remarks        []string `json:"remarks,omitempty"`
	ContactAdmin   []string `json:"admin,omitempty"`   // admin-c, for troubleshooting
	ContactTech    []string `json:"tech,omitempty"`    // tech-c, for troubleshooting
	ContactOwner   []string `json:"owner,omitempty"`   // owner-c
	ContactRouting []string `json:"routing,omitempty"` // routing-c
	ContactAbuse   []string `json:"abuse,omitempty"`   // abuse-c
	NotifiedEmail  []string `json:"notified_email,omitempty"`
	AbuseMailbox   []string `json:"abuse_mailbox,omitempty"`
	MntBy          []string `json:"mnt_by,omitempty"`
	MntLower       string   `json:"mnt_lower,omitempty"`
	MntRoutes      string   `json:"mnt_routes,omitempty"`
	Ref            []string `json:"ref,omitempty"`
	Auth           []string `json:"auth,omitempty"`
	UpdatedDate    string   `json:"updated_date,omitempty"`
	UpdatedDateRaw string   `json:"-"`
	Source         string   `json:"source,omitempty"`
}

func (n *Network) convDate() {
	if len(n.UpdatedDate) > 0 {
		n.UpdatedDateRaw = n.UpdatedDate
		n.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(n.UpdatedDateRaw, wd.WhoisTimeFmt)
	}
}

func (c *Contact) convDate() {
	if len(c.UpdatedDate) > 0 {
		c.UpdatedDateRaw = c.UpdatedDate
		c.UpdatedDate, _ = utils.GuessTimeFmtAndConvert(c.UpdatedDateRaw, wd.WhoisTimeFmt)
	}
}

func NewWhois(parsedWhois *ParsedWhois, rawtext, whoisServer string) *Whois {
	return &Whois{ParsedWhois: parsedWhois, RawText: rawtext, WhoisServer: whoisServer}
}
