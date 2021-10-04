package main

import (
	"log"
	"os"

	"github.com/namsral/flag"
	"github.com/sirupsen/logrus"

	"github.com/shlin168/go-whois/server"
	"github.com/shlin168/go-whois/whois/utils"
)

func main() {
	if err := utils.SetGlobalLoc(); err != nil {
		log.Panic(err)
	}

	fset := flag.NewFlagSetWithEnvPrefix(os.Args[0], "WHOIS", flag.ExitOnError)
	errLogLvl := fset.String("loglvl", "info", "logging level for error log")
	acsLogLvl := fset.String("acsloglvl", "info", "logging level for access log")
	listen := fset.String("listen", ":8080", "listen address")
	metric := fset.String("metric", ":6060", "metric address")
	ipLookupTimeout := fset.Duration("iplookuptimeout", server.DefaultIpLookupTimeout, "ip lookup timeout")
	timeout := fset.Duration("timeout", server.DefaultTimeout, "timeout for WHOIS query, default 5s")
	fset.Parse(os.Args[1:])

	errLogger := logrus.New()
	errLvl, err := logrus.ParseLevel(*errLogLvl)
	if err != nil {
		log.Fatalf("failed to parse error logger level: %v", err)
	}
	errLogger.SetLevel(errLvl)
	acsLogger := logrus.New()
	acsLvl, err := logrus.ParseLevel(*acsLogLvl)
	if err != nil {
		log.Fatalf("failed to parse access logger level: %v", err)
	}
	acsLogger.SetLevel(acsLvl)
	lf := logrus.Fields{
		"errLoglvl":       *errLogLvl,
		"acsLoglvl":       *acsLogLvl,
		"listen":          *listen,
		"metric":          *metric,
		"ipLookupTimeout": *ipLookupTimeout,
		"cacheEnabled":    false,
		"timeout":         *timeout,
	}
	errLogger.WithFields(lf).Info("flag")

	// set server config (with db config) and start server
	serverCfg := server.NewServerCfg(*ipLookupTimeout, *timeout)
	server, err := server.New(serverCfg, errLogger, acsLogger)
	if err != nil {
		log.Panicf("failed to initialize server: %v", err)
	}
	server.Start(*listen, *metric)
}
