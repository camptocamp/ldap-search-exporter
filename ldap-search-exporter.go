package main

import (
  "net/http"
  "sync"
  "time"
  "os"
  "strconv"
  "flag"
  "strings"

  "github.com/prometheus/client_golang/prometheus"
  "github.com/prometheus/common/log"
  "gopkg.in/ldap.v2"
)

type LdapState struct {
  nb map[string]int
  up int
}

type Exporter struct {
  ldap_addr string
  ldap_basedn string
  ldap_queries []string
  minQueryInterval time.Duration
  lastQuery time.Time
  lastState LdapState
  mutex sync.Mutex

  up *prometheus.Desc
  nb *prometheus.GaugeVec
}

func NewExporter(ldap_addr string, ldap_basedn string, ldap_queries []string, minQueryInterval time.Duration) *Exporter {
  return &Exporter{
    ldap_addr: ldap_addr,
    ldap_basedn: ldap_basedn,
    ldap_queries: ldap_queries,
    minQueryInterval: minQueryInterval,

    up: prometheus.NewDesc(
      prometheus.BuildFQName("ldap", "", "up"),
      "Could the LDAP server be reached",
      nil,
      nil),
    nb: prometheus.NewGaugeVec(prometheus.GaugeOpts{
      Namespace: "ldap",
      Name: "nb_results",
      Help: "Number of results to search query",
    }, []string{"query"}),
  }
}

func (exp *Exporter) Describe(ch chan<- *prometheus.Desc) {
  ch <- exp.up
  exp.nb.Describe(ch)
}

func (exp *Exporter) queryLdapServer() LdapState {
  state := exp.lastState
  exp.lastQuery = time.Now()

  l, err := ldap.Dial("tcp", exp.ldap_addr)
	if err != nil {
    log.Fatal(err)
    state.up = 0
    return state
	}
  defer l.Close()

  for _, qry := range exp.ldap_queries {
    req := ldap.NewSearchRequest(
	    exp.ldap_basedn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		  qry, []string{"dn"}, nil,
    )
    sr, err := l.Search(req)
	  if err != nil {
		  log.Fatal(err)
    }

    state.up = 1
    if state.nb == nil { state.nb = make(map[string]int) }
    state.nb[qry] = len(sr.Entries)
  }

  return state
}

func (exp *Exporter) collect(ch chan<- prometheus.Metric) error {

  state := exp.lastState
  if time.Since(exp.lastQuery) >= exp.minQueryInterval {
    state = exp.queryLdapServer()
    exp.lastState = state
  }

  for qry,val := range state.nb {
    exp.nb.WithLabelValues(qry).Set(float64(val))
  }
  exp.nb.Collect(ch)
  ch <- prometheus.MustNewConstMetric(exp.up, prometheus.GaugeValue, float64(state.up))

  return nil
}

func (exp *Exporter) Collect(ch chan<- prometheus.Metric) {
  exp.mutex.Lock() // To protect metrics from concurrent collects.
  defer exp.mutex.Unlock()
  if err := exp.collect(ch); err != nil {
    log.Fatal("Scraping failure!")
  }
  return
}

var (
  ldap_addr = flag.String("ldap.addr", os.Getenv("LDAP_ADDR"), "LDAP server address")
  ldap_basedn = flag.String("ldap.basedn", os.Getenv("LDAP_BASEDN"), "LDAP search base DN")
  ldap_queries = flag.String("ldap.queries", os.Getenv("LDAP_QUERIES"), "LDAP search queries (comma separated)")
  ldap_interval = flag.String("ldap.query.interval", os.Getenv("LDAP_QUERY_INTERVAL"), "Minimum interval between queries to LDAP server in seconds")

  listenAddress = flag.String("listen.address", os.Getenv("LISTEN_ADDRESS"), "")
  metricsEndpoint = flag.String("metrics.endpoint", os.Getenv("METRICS_ENDPOINT"), "")
)

func main() {
  flag.Parse()

  if *ldap_addr == "" { log.Fatal("Missing LDAP server address") }
  if *ldap_basedn == "" { log.Fatal("Missing LDAP search base DN") }
  if *ldap_queries == "" { log.Fatal("Missing LDAP search queries") }

  if *ldap_interval == "" { *ldap_interval = "120" }
  if *listenAddress == "" { *listenAddress = ":9117" }
  if *metricsEndpoint == "" { *metricsEndpoint = "/metrics" }

  ldap_queries_a := strings.Split(*ldap_queries, ",")
  ldap_intervali, err := strconv.Atoi(*ldap_interval)
  if err != nil { log.Fatal("Invalid query interval: %s", *ldap_interval) }
  ldap_intervald := time.Duration(ldap_intervali) * time.Second

  exporter := NewExporter(*ldap_addr, *ldap_basedn, ldap_queries_a, ldap_intervald)
  prometheus.MustRegister(exporter)

  http.Handle(*metricsEndpoint, prometheus.Handler())
  http.HandleFunc("/", func(writer http.ResponseWriter, req *http.Request) {
    writer.Write([]byte("<html><head><title>LDAP search exporter</title></head><body><h1>LDAP search exporter</h1></body></html>"))
  })

  log.Infof("Exporter listening on %s", *listenAddress)

  log.Fatal(http.ListenAndServe(*listenAddress, nil))
}

