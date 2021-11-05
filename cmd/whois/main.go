package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"

	"github.com/shlin168/go-whois/whois"
	"github.com/shlin168/go-whois/whois/utils"
)

const defaultTimeout = 5 * time.Second

func main() {
	if err := utils.SetGlobalLoc(); err != nil {
		log.Panic(err)
	}

	fset := flag.NewFlagSetWithEnvPrefix(os.Args[0], "WHOIS", flag.ExitOnError)
	domainOrIP := fset.String("q", "", "domain to query")
	whoisServer := fset.String("server", "", "optional, specify whois server")
	timeout := fset.Duration("timeout", defaultTimeout, "timeout for WHOIS query, default 5s")
	fset.Parse(os.Args[1:])

	if len(*domainOrIP) == 0 {
		fmt.Println("Usage: ./whois -q <domain or ip>")
		os.Exit(1)
	}

	pwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	xmlPath := filepath.Join(pwd, "cmd/whois/whois-server-list.xml")
	dws, err := whois.NewDomainWhoisServerMap(xmlPath)
	if err != nil {
		log.Fatal(err)
	}

	logger := logrus.New()
	dialer, err := whois.NewClient(
		whois.WithTimeout(*timeout),
		whois.WithServerMap(dws),
		whois.WithErrLogger(logger),
	)
	if err != nil {
		log.Fatal(err)
	}
	if !utils.IsIP(*domainOrIP) {
		pslist, err := utils.GetPublicSuffixs(*domainOrIP)
		if err != nil && len(pslist) == 0 {
			fmt.Println(err)
			os.Exit(1)
		}
		logger.WithFields(logrus.Fields{"query": *domainOrIP, "public_suffixs": pslist}).Info("perform WHOIS query")
		dmWhois, err := dialer.QueryPublicSuffixs(context.Background(), pslist, *whoisServer)
		if err != nil {
			if err != whois.ErrDomainIPNotFound {
				fmt.Println(err)
				os.Exit(1)
			}
			logger.Info(err)
		}
		out, err := json.MarshalIndent(dmWhois, "", "  ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	} else {
		logger.WithFields(logrus.Fields{"query": *domainOrIP}).Info("perform WHOIS query")
		ipWhois, err := dialer.QueryIP(context.Background(), *domainOrIP, *whoisServer)
		if err != nil {
			if err != whois.ErrDomainIPNotFound {
				fmt.Println(err)
				os.Exit(1)
			}
			logger.Info(err)
		}
		out, err := json.MarshalIndent(ipWhois, "", "  ")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(out))
	}
}
