# ldap-search-exporter

Reports the number of results of LDAP search queries. Can be configured using command line parameters or environment variables:

- `--ldap.addr` (`LDAP_ADDR`): ldap server address (ex. localhost:389)
- `--ldap.basedn` (`LDAP_BASEDN`): base DN for ldap search query
- `--ldap.queries` (`LDAP_QUERIES`): coma separated list of search filters (ex. `(objectClass=person)`)
- `--ldap.query.interval` (`LDAP_QUERY_INTERVAL`): minimum interval in seconds between queries to the LDAP server (default = `120`)
- `--listen.address` (`LISTEN_ADDRESS`): IP address and port the exporter should listen on (default = `:9117`)
- `--metrics.endpoint` (`METRICS_ENDPOINT`): URL path the exporter should respond to (default = `/metrics`)
