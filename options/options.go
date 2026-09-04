package options

import (
	"fmt"
	"strings"

	"github.com/jessevdk/go-flags"
)

var Opts struct {
	Bgp               bool           `short:"b" long:"bgp" description:"Connect and Sync with GoBGP server"`
	Ka                string         `short:"k" long:"ka" description:"KeepAlive/BFD RemoteIP:SourceIP:Interval" default:"none"`
	Version           bool           `short:"v" long:"version" description:"Show loxilb version"`
	NoAPI             bool           `short:"a" long:"api" description:"Do not run the Rest API server (the API runs by default; this flag disables it)"`
	NoNlp             bool           `short:"n" long:"nonlp" description:"Do not register with nlp"`
	Host              string         `long:"host" description:"the IP to listen on" default:"0.0.0.0" env:"HOST"`
	Port              int            `long:"port" description:"the port to listen on for insecure connections" default:"11111" env:"PORT"`
	TLS               bool           `long:"tls" description:"enable TLS " env:"TLS"`
	TLSHost           string         `long:"tls-host" description:"the IP to listen on for tls" default:"0.0.0.0" env:"TLS_HOST"`
	TLSPort           int            `long:"tls-port" description:"the port to listen on for secure connections" default:"8091" env:"TLS_PORT"`
	TLSCertificate    flags.Filename `long:"tls-certificate" description:"the certificate to use for secure connections" default:"/opt/loxilb/cert/server.crt" env:"TLS_CERTIFICATE"`
	TLSCertificateKey flags.Filename `long:"tls-key" description:"the private key to use for secure connections" default:"/opt/loxilb/cert/server.key" env:"TLS_PRIVATE_KEY"`
	ClusterNodes      string         `long:"cluster" description:"Comma-separated list of cluter-node IP Addresses" default:"none"`
	ClusterSelf       int            `long:"self" description:"annonation of self in cluster" default:"0"`
	LogLevel          string         `long:"loglevel" description:"One of trace,debug,info,error,warning,notice,critical,emergency,alert" default:"debug"`
	LogDir            string         `long:"log-dir" description:"Directory for loxilb structured log files" default:"/var/log/loxilb/" env:"LOXILB_LOG_DIR"`
	LogFormat         string         `long:"log-format" description:"Log output format: json, text, or both" default:"both" env:"LOXILB_LOG_FORMAT"`
	LogMaxSize        int            `long:"log-max-size" description:"Rotate a log file when it exceeds this many MB (0 disables rotation)" default:"50" env:"LOXILB_LOG_MAX_SIZE"`
	LogMaxBackups     int            `long:"log-max-backups" description:"Rotated files to keep per log, oldest deleted first (0 keeps all until log-max-age)" default:"4" env:"LOXILB_LOG_MAX_BACKUPS"`
	LogMaxAge         int            `long:"log-max-age" description:"Days to retain rotated log files (0 keeps forever)" default:"28" env:"LOXILB_LOG_MAX_AGE"`
	LogNoCompress     bool           `long:"log-no-compress" description:"Do not gzip rotated log files" env:"LOXILB_LOG_NO_COMPRESS"`
	CPUProfile        string         `long:"cpuprofile" description:"Enable cpu profiling and specify file to use" default:"none" env:"CPUPROF"`
	Prometheus        bool           `short:"p" long:"prometheus" description:"Run prometheus thread"`
	CRC32SumDisable   bool           `long:"disable-crc32" description:"Disable crc32 checksum update(experimental)"`
	PassiveEPProbe    bool           `long:"passive-probe" description:"Enable passive liveness probes(experimental)"`
	RssEnable         bool           `long:"rss-enable" description:"Enable rss optimization(experimental)"`
	EgrHooks          bool           `long:"egr-hooks" description:"Enable eBPF egress hooks(experimental)"`
	BgpPeerMode       bool           `short:"r" long:"peer" description:"Run loxilb with goBGP only, no Datapath"`
	BlackList         string         `long:"blacklist" description:"Regex string of blacklisted ports" default:"none"`
	RPC               string         `long:"rpc" description:"RPC mode for syncing - netrpc or grpc" default:"netrpc"`
	K8sAPI            string         `long:"k8s-api" description:"Enable k8s watcher(experimental)" default:"none"`
	IPVSCompat        bool           `long:"ipvs-compat" description:"Enable ipvs-compat(experimental)"`
	FallBack          bool           `long:"fallback" description:"Fallback to system default networking(experimental)"`
	LocalSockPolicy   bool           `long:"localsockpolicy" description:"support local socket policies (experimental)"`
	SockMapSupport    bool           `long:"sockmapsupport" description:"Support sockmap based L4 proxying (experimental)"`
	KtlsSupport       bool           `long:"ktlssupport" description:"Support kernel TLS offload for HTTPS sockmap (experimental)"`
	Cloud             string         `long:"cloud" description:"cloud type if any e.g aws,ncloud" default:"on-prem"`
	CloudCIDRBlock    string         `long:"cloudcidrblock" description:"cloud implementations need VIP cidr blocks(experimental)"`
	CloudInstance     string         `long:"cloudinstance" description:"instance-name to distinguish instance sets running in a same cloud-region"`
	ConfigPath        string         `long:"config-path" description:"Config file path" default:"/etc/loxilb/"`
	ConfigAutoPersist string         `long:"config-auto-persist" description:"Debounced write-through of the running config to snapshot.json after successful mutating API calls (on/off)" choice:"on" choice:"off" default:"on"`
	ProxyModeOnly     bool           `long:"proxyonlymode" description:"Run loxilb in proxy mode only, no Datapath"`
	WhiteList         string         `long:"whitelist" description:"Regex string of whitelisted interface(experimental)" default:"none"`
	ClusterInterface  string         `long:"clusterinterface" description:"cluster interface for egress HA" default:""`
	UserServiceEnable bool           `long:"userservice" description:"Enable user service for loxilb"`

	// Management-plane store (PostgreSQL, shared server with loxilb-oam).
	//
	// Replaces the --database* family, which addressed MySQL/MariaDB. One
	// database technology is in the product now, and the two planes reach the
	// same server through different roles and different schemas: this side
	// holds users and session tokens in aigw_mgmt under aigw_mgmt_user, and
	// cannot see the data plane's tables at all.
	//
	// --userservice remains the enable flag for this plane, so unlike the
	// key-store family below these options carry defaults.
	//
	// The password is never a flag value — it would be readable in
	// /proc/*/cmdline by every local process. Use the file or the environment.
	MgmtDBHost         string `long:"mgmt-db-host" description:"Management store host (PostgreSQL)" default:"127.0.0.1"`
	MgmtDBPort         string `long:"mgmt-db-port" description:"Management store port" default:"5432"`
	MgmtDBUser         string `long:"mgmt-db-user" description:"Management store role" default:"aigw_mgmt_user"`
	MgmtDBName         string `long:"mgmt-db-name" description:"Management store database" default:"loxilb"`
	MgmtDBPasswordPath string `long:"mgmt-db-password-file" description:"File holding the management store password" default:"/etc/loxilb/mgmt_db_password"`
	MgmtSSLOption      bool   `long:"mgmt-db-ssl" description:"Require verified TLS to the management store"`
	MgmtSSLCACert      string `long:"mgmt-db-ssl-ca-cert-file" description:"CA certificate for the management store connection"`
	MgmtSSLClientCert  string `long:"mgmt-db-ssl-client-cert-file" description:"Client certificate for the management store connection"`
	MgmtSSLClientKey   string `long:"mgmt-db-ssl-client-key-file" description:"Client key for the management store connection"`

	// AI data-plane API-key store (PostgreSQL, shared server with loxilb-oam).
	//
	// Deliberately separate from the --database* block above, which configures
	// the management plane: the two planes must be able to fail, be maintained
	// and be credentialed independently.
	//
	// There is no enable boolean. These options carry no host default, so an
	// empty AIKeyDBHost is an unambiguous "store not configured"; enforcement
	// is a per-service policy set through the API, not a process flag.
	//
	// The password is never a flag value — it would be readable in
	// /proc/*/cmdline by every local process. Use the file or the environment.
	AIKeyDBHost         string `long:"aikey-db-host" description:"AI API-key store host (PostgreSQL)"`
	AIKeyDBPort         string `long:"aikey-db-port" description:"AI API-key store port" default:"5432"`
	AIKeyDBUser         string `long:"aikey-db-user" description:"AI API-key store role"`
	AIKeyDBName         string `long:"aikey-db-name" description:"AI API-key store database"`
	AIKeyDBPasswordPath string `long:"aikey-db-password-file" description:"File holding the API-key store password"`
	AIKeySSLOption      bool   `long:"aikey-db-ssl" description:"Require verified TLS to the API-key store"`
	AIKeySSLCACert      string `long:"aikey-db-ssl-ca-cert-file" description:"CA certificate for the API-key store connection"`
	AIKeySSLClientCert  string `long:"aikey-db-ssl-client-cert-file" description:"Client certificate for the API-key store connection"`
	AIKeySSLClientKey   string `long:"aikey-db-ssl-client-key-file" description:"Client key for the API-key store connection"`

	// manual token
	ManualTokenEnable bool   `long:"manualtoken" description:"Enable manual token service for loxilb"`
	ManualTokenPath   string `long:"manualtokenvalue" description:"Path of manual token " default:"/etc/loxilb/manual_token"`

	// Oauth2 Options as input arguemtns
	Oauth2Enable   bool   `long:"oauth2" description:"Enable user oauth2 service for loxilb"`
	Oauth2Provider string `long:"oauth2provider" description:"Oauth2 provider names, comma-separated" default:"google"`

	// KV Cache Agent
	KVAgentAddr string `long:"kv-agent-addr" description:"KV agent REST address for auto-discovery override" default:"" env:"KV_AGENT_ADDR"`

	// DPU plugin
	DpuPlugin    string `long:"dpu-plugin" description:"DPU plugin to activate (e.g., doca-bf2)" default:"" env:"DPU_PLUGIN"`
	DocaTcpAging uint32 `long:"doca-tcp-aging" description:"DOCA TCP CT entry idle timeout (seconds)" default:"120" env:"DOCA_TCP_AGING"`
	DocaUdpAging uint32 `long:"doca-udp-aging" description:"DOCA UDP CT entry idle timeout (seconds)" default:"30" env:"DOCA_UDP_AGING"`
	DocaAiAging  uint32 `long:"doca-ai-aging" description:"DOCA AI/SSE CT entry idle timeout (seconds)" default:"3600" env:"DOCA_AI_AGING"`

	// DOCA counter configuration.
	// PerEpSharedCounters: gate per-EP SHARED counter lifecycle.
	//   Default false — no production BASIC pipe uses SHARED counters today.
	//   Set true to activate ensureEpSharedCounter / releaseEpSharedCounter hooks
	//   when a future v6.x phase introduces protocol-pipe SHARED pools.
	DocaPerEpSharedCounters bool `long:"doca-per-ep-shared-counters" description:"Enable per-EP SHARED counter lifecycle (default off)" env:"DOCA_PER_EP_SHARED_COUNTERS"`

	// Oauth2 secure informations
	Oauth2GoogleClientID     string `long:"oauth2google-clientid" description:"Oauth2 google client id" env:"OAUTH2_GOOGLE_CLIENT_ID"`
	Oauth2GoogleClientSecret string `long:"oauth2google-clientsecret" description:"Oauth2 google client secret" env:"OAUTH2_GOOGLE_CLIENT_SECRET"`
	Oauth2GoogleRedirectURL  string `long:"oauth2google-redirecturl" description:"Oauth2 google redirect url" env:"OAUTH2_GOOGLE_REDIRECT_URL"`
	Oauth2GithubClientID     string `long:"oauth2github-clientid" description:"Oauth2 github client id" env:"OAUTH2_GITHUB_CLIENT_ID"`
	Oauth2GithubClientSecret string `long:"oauth2github-clientsecret" description:"Oauth2 github client secret" env:"OAUTH2_GITHUB_CLIENT_SECRET"`
	Oauth2GithubRedirectURL  string `long:"oauth2github-redirecturl" description:"Oauth2 github redirect url" env:"OAUTH2_GITHUB_REDIRECT_URL"`
}

// ValidateOpts checks if the required environment variables are set when Oauth2Enable is true
func ValidateOpts() error {
	// Check if Oauth2Enable is true
	if Opts.Oauth2Enable {
		// Split the Oauth2Provider string into a slice of providers
		providers := strings.Split(Opts.Oauth2Provider, ",")

		// Iterate over each provider and validate the required environment variables
		for _, provider := range providers {
			switch provider {
			case "google":
				if Opts.Oauth2GoogleClientID == "" || Opts.Oauth2GoogleClientSecret == "" || Opts.Oauth2GoogleRedirectURL == "" {
					return fmt.Errorf("Oauth2 google client id, client secret and redirect url are required but not set")
				}
			case "github":
				if Opts.Oauth2GithubClientID == "" || Opts.Oauth2GithubClientSecret == "" || Opts.Oauth2GithubRedirectURL == "" {
					return fmt.Errorf("Oauth2 github client id, client secret and redirect url are required but not set")
				}
			default:
				return fmt.Errorf("unsupported oauth2 provider: %s", provider)
			}
		}
	}
	return nil
}
