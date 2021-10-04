package whois

import (
	"log"
	"net"
	"strings"
	"time"
)

var (
	TestTimeoutDomain      = "timeout.aaa"
	TestTimeoutIP          = "85.34.28.46"
	TestNotFoundDomain     = "abc.app"
	TestDomain             = "github.io"
	TestDomainWhoisRawText = `Domain Name: github.io
Registry Domain ID: D503300000040351827-LRMS
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: www.markmonitor.com
Updated Date: 2021-02-04T02:17:45-0800
Creation Date: 2013-03-08T11:41:10-0800
Registrar Registration Expiration Date: 2023-03-08T00:00:00-0800
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Registrant Organization: GitHub, Inc.
Registrant State/Province: CA
Registrant Country: US
Registrant Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.io
Admin Organization: GitHub, Inc.
Admin State/Province: CA
Admin Country: US
Admin Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.io
Tech Organization: GitHub, Inc.
Tech State/Province: CA
Tech Country: US
Tech Email: Select Request Email Form at https://domains.markmonitor.com/whois/github.io
Name Server: dns3.p05.nsone.net
Name Server: dns1.p05.nsone.net
Name Server: ns-692.awsdns-22.net
Name Server: dns2.p05.nsone.net
Name Server: ns-1622.awsdns-10.co.uk
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2021-07-20T06:46:30-0700
`
	TestNotFoundIP     = "80.20.14.56"
	TestIP             = "20.11.10.87"
	TestIPWhoisRawText = `% This is the RIPE Database query service.
% The objects are in RPSL format.
%
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

% Note: this output has been filtered.
% To receive output for a database update, use the "-B" flag.

% Information related to '80.11.10.0 - 80.11.10.255'

% Abuse contact for '80.11.10.0 - 80.11.10.255' is 'gestionip.ft<?)orange.com'

inetnum: 80.11.10.0 - 80.11.10.255
netname: IP2000-ADSL-BAS
descr: LNNLY657 Neuilly Bloc 1
country: FR
admin-c: WITR1-RIPE
tech-c: WITR1-RIPE
status: ASSIGNED PA
remarks: for hacking, spamming or security problems send mail to
remarks: abuse<?)orange.fr
mnt-by: FT-BRX
created: 2010-03-24T10:12:12Z
last-modified: 2019-04-25T07:54:55Z
source: RIPE

role: Wanadoo France Technical Role
address: FRANCE TELECOM/SCR
address: 48 rue Camille Desmoulins
address: 92791 ISSY LES MOULINEAUX CEDEX 9
address: FR
phone: +33 1 58 88 50 00
abuse-mailbox: abuse<?)orange.fr
admin-c: BRX1-RIPE
tech-c: BRX1-RIPE
nic-hdl: WITR1-RIPE
mnt-by: FT-BRX
created: 2001-12-04T17:57:08Z
last-modified: 2013-07-16T14:09:50Z
source: RIPE # Filtered

% Information related to '80.11.0.0/16AS3215'

route: 80.11.0.0/16
descr: France Telecom
descr: Wanadoo France
remarks: -------------------------------------------
remarks: For Hacking, Spamming or Security problems
remarks: send mail to abuse<?)wanadoo.fr
remarks: -------------------------------------------
origin: AS3215
mnt-by: RAIN-TRANSPAC
mnt-by: FT-BRX
created: 2012-11-20T14:15:56Z
last-modified: 2012-11-20T14:15:56Z
source: RIPE

% This query was served by the RIPE Database Query Service version 1.101 (BLAARKOP)
`
)

// StartTCPServer is used to start mock WHOIS TCP server
func StartTCPServer(addr string, handler func(net.Conn)) (net.Listener, error) {
	// Listen for incoming connections.
	var server net.Listener
	var err error
	done := make(chan bool)
	go func() {
		server, err = net.Listen("tcp", addr)
		if err != nil {
			log.Panic(err)
		}
		close(done)
		for {
			// Listen for an incoming connection.
			conn, _ := server.Accept()
			// Handle connections in a new goroutine.
			go handler(conn)
		}
	}()
	<-done
	return server, nil
}

// StartMockWhoisServer starts mock whois server for testing
func StartMockWhoisServer(addr string, handlers ...func(net.Conn)) (net.Listener, error) {
	var handler func(net.Conn)
	if len(handlers) == 0 {
		handler = func(conn net.Conn) {
			if conn != nil {
				var bs = make([]byte, 1024)
				n, _ := conn.Read(bs)
				switch strings.TrimSpace(string(bs[:n])) {
				case TestDomain:
					conn.Write([]byte(TestDomainWhoisRawText))
				case TestNotFoundDomain:
					conn.Write([]byte("No match for " + TestNotFoundDomain))
				case TestIP:
					conn.Write([]byte(TestIPWhoisRawText))
				case TestNotFoundIP:
					conn.Write([]byte("No match found for " + TestNotFoundIP))
				case TestTimeoutDomain:
					time.Sleep(3 * time.Second)
					conn.Write([]byte("No match for " + TestTimeoutDomain))
				case TestTimeoutIP:
					time.Sleep(3 * time.Second)
					conn.Write([]byte("No match found for " + TestTimeoutIP))
				}
				conn.Close()
			}
		}
	} else {
		handler = handlers[0]
	}
	server, err := StartTCPServer(addr, handler)
	if err != nil {
		return nil, err
	}
	return server, nil
}
