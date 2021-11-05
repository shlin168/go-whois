package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/shlin168/go-whois/whois"
)

const (
	apiWhoisPath = "/whois"
)

var (
	errStop = errors.New("stop")

	DefaultIpLookupTimeout = 2 * time.Second
	DefaultTimeout         = 5 * time.Second
)

type ServerCfg struct {
	ipLookupTimeout time.Duration
	whoisTimeout    time.Duration
}

func NewServerCfg(iptimeout, timeout time.Duration) *ServerCfg {
	return &ServerCfg{
		ipLookupTimeout: iptimeout,
		whoisTimeout:    timeout,
	}
}

// Server is whois api server to interact with database, cache, logger, ...
type Server struct {
	resolver  *Resolver
	cli       *whois.Client
	reg       prometheus.Registerer
	acsLogger logrus.FieldLogger
	errLogger logrus.FieldLogger
	stop      chan struct{}
	Killed    chan struct{}
}

// New initialize whois api server
func New(cfg *ServerCfg, errLogger, acsLogger logrus.FieldLogger) (*Server, error) {
	s := &Server{
		resolver:  NewResolver(cfg.ipLookupTimeout),
		errLogger: errLogger,
		acsLogger: acsLogger,
	}
	// Initialize domain whois server map from URL
	whoisServer, err := whois.NewDomainWhoisServerMap(whois.WhoisServerListURL)
	if err != nil {
		return nil, err
	}
	// Realtime Whois - default query
	s.cli, err = whois.NewClient(
		whois.WithTimeout(cfg.whoisTimeout),
		whois.WithServerMap(whoisServer),
		whois.WithErrLogger(errLogger),
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// addPprof adds /debug/pprof/... to mux.
func addPprof(mux *mux.Router) {
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
}

// Start starts whois api server and listen for the stop signal to control lifetime of server
func (s *Server) Start(servAddr, metricAddr string) {
	s.stop = make(chan struct{})
	s.Killed = make(chan struct{})
	g, ctx := errgroup.WithContext(context.Background())
	stopSig := make(chan os.Signal, 1)
	signal.Notify(stopSig, syscall.SIGINT, syscall.SIGTERM)

	// Initialize metrics server
	MetricMux := mux.NewRouter()
	addPprof(MetricMux)
	MetricMux.Handle("/metrics", promhttp.Handler())
	metric := &http.Server{Addr: metricAddr, Handler: MetricMux}
	MetricRegister(s.reg)

	// Start metrics
	s.errLogger.WithField("address", metricAddr).Info("enable metric")
	g.Go(func() error {
		return metric.ListenAndServe()
	})

	// Initialize service server
	router := mux.NewRouter()
	router.HandleFunc(apiWhoisPath, MetricMiddleware(
		WhoisHandler(s.cli, s.resolver, s.acsLogger))).
		Methods(http.MethodPost)

	service := &http.Server{Addr: servAddr, Handler: router}

	// Start service
	s.errLogger.WithField("address", servAddr).Info("start service")
	g.Go(func() error {
		return service.ListenAndServe()
	})

	// Wait for stop signal
	g.Go(func() error {
		select {
		case <-stopSig:
			return errStop
		case <-s.stop:
			return errStop
		}
	})

	// Stop everything
	var shutdownErr error
	g.Go(func() error {
		<-ctx.Done()
		s.errLogger.Info("shut down service")
		shutdownErr = multierror.Append(shutdownErr, service.Shutdown(context.Background()))

		s.errLogger.Info("shut down metric")
		MetricUnRegister(s.reg)
		shutdownErr = multierror.Append(shutdownErr, metric.Shutdown(context.Background()))
		return shutdownErr
	})

	if err := g.Wait(); err != nil && !errors.Is(err, errStop) {
		log.Panic(s.errLogger, "failed to serve", err)
	}
	s.errLogger.Info("Server exit")
	close(s.Killed)
}

// Close will close the server and wait for fully killed signal
func (s *Server) Close() {
	close(s.stop)
	<-s.Killed
}
