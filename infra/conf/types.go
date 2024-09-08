package conf

import (
	"encoding/json"

	"github.com/xtls/xray-core/infra/conf/cfgcommon/duration"
)

var (
	inboundConfigLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"dokodemo-door": func() interface{} { return new(DokodemoConfig) },
		"http":          func() interface{} { return new(HTTPServerConfig) },
		"shadowsocks":   func() interface{} { return new(ShadowsocksServerConfig) },
		"socks":         func() interface{} { return new(SocksServerConfig) },
		"vless":         func() interface{} { return new(VLessInboundConfig) },
		"vmess":         func() interface{} { return new(VMessInboundConfig) },
		"trojan":        func() interface{} { return new(TrojanServerConfig) },
		"wireguard":     func() interface{} { return &WireGuardConfig{IsClient: false} },
	}, "protocol", "settings")

	outboundConfigLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"blackhole":   func() interface{} { return new(BlackholeConfig) },
		"loopback":    func() interface{} { return new(LoopbackConfig) },
		"freedom":     func() interface{} { return new(FreedomConfig) },
		"http":        func() interface{} { return new(HTTPClientConfig) },
		"shadowsocks": func() interface{} { return new(ShadowsocksClientConfig) },
		"socks":       func() interface{} { return new(SocksClientConfig) },
		"vless":       func() interface{} { return new(VLessOutboundConfig) },
		"vmess":       func() interface{} { return new(VMessOutboundConfig) },
		"trojan":      func() interface{} { return new(TrojanClientConfig) },
		"dns":         func() interface{} { return new(DNSOutboundConfig) },
		"wireguard":   func() interface{} { return &WireGuardConfig{IsClient: true} },
	}, "protocol", "settings")

	kcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none":         func() interface{} { return new(NoOpAuthenticator) },
		"srtp":         func() interface{} { return new(SRTPAuthenticator) },
		"utp":          func() interface{} { return new(UTPAuthenticator) },
		"wechat-video": func() interface{} { return new(WechatVideoAuthenticator) },
		"dtls":         func() interface{} { return new(DTLSAuthenticator) },
		"wireguard":    func() interface{} { return new(WireguardAuthenticator) },
		"dns":          func() interface{} { return new(DNSAuthenticator) },
	}, "type", "")

	tcpHeaderLoader = NewJSONConfigLoader(ConfigCreatorCache{
		"none": func() interface{} { return new(NoOpConnectionAuthenticator) },
		"http": func() interface{} { return new(Authenticator) },
	}, "type", "")
)

type SniffingConfig struct {
	Enabled         bool        `json:"enabled"`
	DestOverride    *StringList `json:"destOverride"`
	DomainsExcluded *StringList `json:"domainsExcluded"`
	MetadataOnly    bool        `json:"metadataOnly"`
	RouteOnly       bool        `json:"routeOnly"`
}


type MuxConfig struct {
	Enabled         bool   `json:"enabled"`
	Concurrency     int16  `json:"concurrency"`
	XudpConcurrency int16  `json:"xudpConcurrency"`
	XudpProxyUDP443 string `json:"xudpProxyUDP443"`
}


type InboundDetourAllocationConfig struct {
	Strategy    string  `json:"strategy"`
	Concurrency *uint32 `json:"concurrency"`
	RefreshMin  *uint32 `json:"refresh"`
}

type InboundDetourConfig struct {
	Protocol       string                         `json:"protocol"`
	PortList       *PortList                      `json:"port"`
	ListenOn       *Address                       `json:"listen"`
	Settings       *json.RawMessage               `json:"settings"`
	Tag            string                         `json:"tag"`
	Allocation     *InboundDetourAllocationConfig `json:"allocate"`
	StreamSetting  *StreamConfig                  `json:"streamSettings"`
	DomainOverride *StringList                    `json:"domainOverride"`
	SniffingConfig *SniffingConfig                `json:"sniffing"`
}

type OutboundDetourConfig struct {
	Protocol      string           `json:"protocol"`
	SendThrough   *string          `json:"sendThrough"`
	Tag           string           `json:"tag"`
	Settings      *json.RawMessage `json:"settings"`
	StreamSetting *StreamConfig    `json:"streamSettings"`
	ProxySettings *ProxyConfig     `json:"proxySettings"`
	MuxSettings   *MuxConfig       `json:"mux"`
}

type StatsConfig struct{}

type Config struct {
	// Port of this Point server.
	// Deprecated: Port exists for historical compatibility
	// and should not be used.
	Port uint16 `json:"port"`

	// Deprecated: Global transport config is no longer used
	// left for returning error
	Transport        map[string]json.RawMessage `json:"transport"`

	LogConfig        *LogConfig              `json:"log"`
	RouterConfig     *RouterConfig           `json:"routing"`
	DNSConfig        *DNSConfig              `json:"dns"`
	InboundConfigs   []InboundDetourConfig   `json:"inbounds"`
	OutboundConfigs  []OutboundDetourConfig  `json:"outbounds"`
	Policy           *PolicyConfig           `json:"policy"`
	API              *APIConfig              `json:"api"`
	Metrics          *MetricsConfig          `json:"metrics"`
	Stats            *StatsConfig            `json:"stats"`
	Reverse          *ReverseConfig          `json:"reverse"`
	FakeDNS          *FakeDNSConfig          `json:"fakeDns"`
	Observatory      *ObservatoryConfig      `json:"observatory"`
	BurstObservatory *BurstObservatoryConfig `json:"burstObservatory"`
}

// TrojanServerTarget is configuration of a single trojan server
type TrojanServerTarget struct {
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Level    byte     `json:"level"`
	Flow     string   `json:"flow"`
}

// TrojanClientConfig is configuration of trojan servers
type TrojanClientConfig struct {
	Servers []*TrojanServerTarget `json:"servers"`
}

// TrojanInboundFallback is fallback configuration
type TrojanInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

// TrojanUserConfig is user configuration
type TrojanUserConfig struct {
	Password string `json:"password"`
	Level    byte   `json:"level"`
	Email    string `json:"email"`
	Flow     string `json:"flow"`
}

// TrojanServerConfig is Inbound configuration
type TrojanServerConfig struct {
	Clients   []*TrojanUserConfig      `json:"clients"`
	Fallback  *TrojanInboundFallback   `json:"fallback"`
	Fallbacks []*TrojanInboundFallback `json:"fallbacks"`
}

type VLessInboundFallback struct {
	Name string          `json:"name"`
	Alpn string          `json:"alpn"`
	Path string          `json:"path"`
	Type string          `json:"type"`
	Dest json.RawMessage `json:"dest"`
	Xver uint64          `json:"xver"`
}

type VLessInboundConfig struct {
	Clients    []json.RawMessage       `json:"clients"`
	Decryption string                  `json:"decryption"`
	Fallback   *VLessInboundFallback   `json:"fallback"`
	Fallbacks  []*VLessInboundFallback `json:"fallbacks"`
}

type VLessOutboundVnext struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VLessOutboundConfig struct {
	Vnext []*VLessOutboundVnext `json:"vnext"`
}

type VMessAccount struct {
	ID          string `json:"id"`
	Security    string `json:"security"`
	Experiments string `json:"experiments"`
}

type VMessDetourConfig struct {
	ToTag string `json:"to"`
}


type FeaturesConfig struct {
	Detour *VMessDetourConfig `json:"detour"`
}

type VMessDefaultConfig struct {
	Level byte `json:"level"`
}

type VMessInboundConfig struct {
	Users        []json.RawMessage   `json:"clients"`
	Features     *FeaturesConfig     `json:"features"`
	Defaults     *VMessDefaultConfig `json:"default"`
	DetourConfig *VMessDetourConfig  `json:"detour"`
}

type VMessOutboundTarget struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type VMessOutboundConfig struct {
	Receivers []*VMessOutboundTarget `json:"vnext"`
}

type KCPConfig struct {
	Mtu             *uint32         `json:"mtu"`
	Tti             *uint32         `json:"tti"`
	UpCap           *uint32         `json:"uplinkCapacity"`
	DownCap         *uint32         `json:"downlinkCapacity"`
	Congestion      *bool           `json:"congestion"`
	ReadBufferSize  *uint32         `json:"readBufferSize"`
	WriteBufferSize *uint32         `json:"writeBufferSize"`
	HeaderConfig    json.RawMessage `json:"header"`
	Seed            *string         `json:"seed"`
}

type TCPConfig struct {
	HeaderConfig        json.RawMessage `json:"header"`
	AcceptProxyProtocol bool            `json:"acceptProxyProtocol"`
}

type WebSocketConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
}

type HttpUpgradeConfig struct {
	Host                string            `json:"host"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
}


type SplitHTTPConfig struct {
	Host                 string            `json:"host"`
	Path                 string            `json:"path"`
	Headers              map[string]string `json:"headers"`
	ScMaxConcurrentPosts *Int32Range       `json:"scMaxConcurrentPosts"`
	ScMaxEachPostBytes   *Int32Range       `json:"scMaxEachPostBytes"`
	ScMinPostsIntervalMs *Int32Range       `json:"scMinPostsIntervalMs"`
	NoSSEHeader          bool              `json:"noSSEHeader"`
	XPaddingBytes        *Int32Range       `json:"xPaddingBytes"`
}

type HTTPConfig struct {
	Host               *StringList            `json:"host"`
	Path               string                 `json:"path"`
	ReadIdleTimeout    int32                  `json:"read_idle_timeout"`
	HealthCheckTimeout int32                  `json:"health_check_timeout"`
	Method             string                 `json:"method"`
	Headers            map[string]*StringList `json:"headers"`
}

type TLSCertConfig struct {
	CertFile       string   `json:"certificateFile"`
	CertStr        []string `json:"certificate"`
	KeyFile        string   `json:"keyFile"`
	KeyStr         []string `json:"key"`
	Usage          string   `json:"usage"`
	OcspStapling   uint64   `json:"ocspStapling"`
	OneTimeLoading bool     `json:"oneTimeLoading"`
	BuildChain     bool     `json:"buildChain"`
}

type TLSConfig struct {
	Insecure                             bool             `json:"allowInsecure"`
	Certs                                []*TLSCertConfig `json:"certificates"`
	ServerName                           string           `json:"serverName"`
	ALPN                                 *StringList      `json:"alpn"`
	EnableSessionResumption              bool             `json:"enableSessionResumption"`
	DisableSystemRoot                    bool             `json:"disableSystemRoot"`
	MinVersion                           string           `json:"minVersion"`
	MaxVersion                           string           `json:"maxVersion"`
	CipherSuites                         string           `json:"cipherSuites"`
	Fingerprint                          string           `json:"fingerprint"`
	RejectUnknownSNI                     bool             `json:"rejectUnknownSni"`
	PinnedPeerCertificateChainSha256     *[]string        `json:"pinnedPeerCertificateChainSha256"`
	PinnedPeerCertificatePublicKeySha256 *[]string        `json:"pinnedPeerCertificatePublicKeySha256"`
	MasterKeyLog                         string           `json:"masterKeyLog"`
}

type REALITYConfig struct {
	Show         bool            `json:"show"`
	MasterKeyLog string          `json:"masterKeyLog"`
	Dest         json.RawMessage `json:"dest"`
	Type         string          `json:"type"`
	Xver         uint64          `json:"xver"`
	ServerNames  []string        `json:"serverNames"`
	PrivateKey   string          `json:"privateKey"`
	MinClientVer string          `json:"minClientVer"`
	MaxClientVer string          `json:"maxClientVer"`
	MaxTimeDiff  uint64          `json:"maxTimeDiff"`
	ShortIds     []string        `json:"shortIds"`

	Fingerprint string `json:"fingerprint"`
	ServerName  string `json:"serverName"`
	PublicKey   string `json:"publicKey"`
	ShortId     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type CustomSockoptConfig struct {
	Level string `json:"level"`
	Opt   string `json:"opt"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type SocketConfig struct {
	Mark                 int32                  `json:"mark"`
	TFO                  interface{}            `json:"tcpFastOpen"`
	TProxy               string                 `json:"tproxy"`
	AcceptProxyProtocol  bool                   `json:"acceptProxyProtocol"`
	DomainStrategy       string                 `json:"domainStrategy"`
	DialerProxy          string                 `json:"dialerProxy"`
	TCPKeepAliveInterval int32                  `json:"tcpKeepAliveInterval"`
	TCPKeepAliveIdle     int32                  `json:"tcpKeepAliveIdle"`
	TCPCongestion        string                 `json:"tcpCongestion"`
	TCPWindowClamp       int32                  `json:"tcpWindowClamp"`
	TCPMaxSeg            int32                  `json:"tcpMaxSeg"`
	TcpNoDelay           bool                   `json:"tcpNoDelay"`
	TCPUserTimeout       int32                  `json:"tcpUserTimeout"`
	V6only               bool                   `json:"v6only"`
	Interface            string                 `json:"interface"`
	TcpMptcp             bool                   `json:"tcpMptcp"`
	CustomSockopt        []*CustomSockoptConfig `json:"customSockopt"`
}

type StreamConfig struct {
	Network             *TransportProtocol  `json:"network"`
	Security            string              `json:"security"`
	TLSSettings         *TLSConfig          `json:"tlsSettings"`
	REALITYSettings     *REALITYConfig      `json:"realitySettings"`
	TCPSettings         *TCPConfig          `json:"tcpSettings"`
	KCPSettings         *KCPConfig          `json:"kcpSettings"`
	WSSettings          *WebSocketConfig    `json:"wsSettings"`
	HTTPSettings        *HTTPConfig         `json:"httpSettings"`
	SocketSettings      *SocketConfig       `json:"sockopt"`
	GRPCConfig          *GRPCConfig         `json:"grpcSettings"`
	GUNConfig           *GRPCConfig         `json:"gunSettings"`
	HTTPUPGRADESettings *HttpUpgradeConfig  `json:"httpupgradeSettings"`
	SplitHTTPSettings   *SplitHTTPConfig    `json:"splithttpSettings"`
}

type ProxyConfig struct {
	Tag string `json:"tag"`

	// TransportLayerProxy: For compatibility.
	TransportLayerProxy bool `json:"transportLayer"`
}

type APIConfig struct {
	Tag      string   `json:"tag"`
	Listen   string   `json:"listen"`
	Services []string `json:"services"`
}


type GRPCConfig struct {
	Authority           string `json:"authority"`
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	IdleTimeout         int32  `json:"idle_timeout"`
	HealthCheckTimeout  int32  `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int32  `json:"initial_windows_size"`
	UserAgent           string `json:"user_agent"`
}

type FreedomConfig struct {
	DomainStrategy string    `json:"domainStrategy"`
	Timeout        *uint32   `json:"timeout"`
	Redirect       string    `json:"redirect"`
	UserLevel      uint32    `json:"userLevel"`
	Fragment       *Fragment `json:"fragment"`
	Noise          *Noise    `json:"noise"`
	ProxyProtocol  uint32    `json:"proxyProtocol"`
}

type Fragment struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
}

type Noise struct {
	Packet string `json:"packet"`
	Delay  string `json:"delay"`
}

type HTTPAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}

type HTTPServerConfig struct {
	Timeout     uint32         `json:"timeout"`
	Accounts    []*HTTPAccount `json:"accounts"`
	Transparent bool           `json:"allowTransparent"`
	UserLevel   uint32         `json:"userLevel"`
}


type NameServerConfig struct {
	Address       *Address
	ClientIP      *Address
	Port          uint16
	SkipFallback  bool
	Domains       []string
	ExpectIPs     StringList
	QueryStrategy string
}

// DNSConfig is a JSON serializable object for dns.Config.
type DNSConfig struct {
	Servers                []*NameServerConfig `json:"servers"`
	Hosts                  *HostsWrapper       `json:"hosts"`
	ClientIP               *Address            `json:"clientIp"`
	Tag                    string              `json:"tag"`
	QueryStrategy          string              `json:"queryStrategy"`
	DisableCache           bool                `json:"disableCache"`
	DisableFallback        bool                `json:"disableFallback"`
	DisableFallbackIfMatch bool                `json:"disableFallbackIfMatch"`
}

type HostAddress struct {
	addr  *Address
	addrs []*Address
}

type HostsWrapper struct {
	Hosts map[string]*HostAddress
}

type FakeDNSPoolElementConfig struct {
	IPPool  string `json:"ipPool"`
	LRUSize int64  `json:"poolSize"`
}

type FakeDNSConfig struct {
	pool  *FakeDNSPoolElementConfig
	pools []*FakeDNSPoolElementConfig
}

type NoneResponse struct{}

type HTTPResponse struct{}

type BlackholeConfig struct {
	Response json.RawMessage `json:"response"`
}

type NoOpAuthenticator struct{}

type NoOpConnectionAuthenticator struct{}

type SRTPAuthenticator struct{}

type UTPAuthenticator struct{}

type WechatVideoAuthenticator struct{}

type WireguardAuthenticator struct{}


type DNSAuthenticator struct {
	Domain string `json:"domain"`
}

type DTLSAuthenticator struct{}

type AuthenticatorRequest struct {
	Version string                 `json:"version"`
	Method  string                 `json:"method"`
	Path    StringList             `json:"path"`
	Headers map[string]*StringList `json:"headers"`
}

type AuthenticatorResponse struct {
	Version string                 `json:"version"`
	Status  string                 `json:"status"`
	Reason  string                 `json:"reason"`
	Headers map[string]*StringList `json:"headers"`
}

type Authenticator struct {
	Request  AuthenticatorRequest  `json:"request"`
	Response AuthenticatorResponse `json:"response"`
}


type RouterRulesConfig struct {
	RuleList       []json.RawMessage `json:"rules"`
	DomainStrategy string            `json:"domainStrategy"`
}

// StrategyConfig represents a strategy config
type StrategyConfig struct {
	Type     string           `json:"type"`
	Settings *json.RawMessage `json:"settings"`
}

type BalancingRule struct {
	Tag         string         `json:"tag"`
	Selectors   StringList     `json:"selector"`
	Strategy    StrategyConfig `json:"strategy"`
	FallbackTag string         `json:"fallbackTag"`
}


type RouterConfig struct {
	Settings       *RouterRulesConfig `json:"settings"` // Deprecated
	RuleList       []json.RawMessage  `json:"rules"`
	DomainStrategy *string            `json:"domainStrategy"`
	Balancers      []*BalancingRule   `json:"balancers"`

	DomainMatcher string `json:"domainMatcher"`
}

type RouterRule struct {
	RuleTag     string `json:"ruleTag"`
	Type        string `json:"type"`
	OutboundTag string `json:"outboundTag"`
	BalancerTag string `json:"balancerTag"`

	DomainMatcher string `json:"domainMatcher"`
}

type LogConfig struct {
	AccessLog string `json:"access"`
	ErrorLog  string `json:"error"`
	LogLevel  string `json:"loglevel"`
	DNSLog    bool   `json:"dnsLog"`
}

type DokodemoConfig struct {
	Host         *Address     `json:"address"`
	PortValue    uint16       `json:"port"`
	NetworkList  *NetworkList `json:"network"`
	TimeoutValue uint32       `json:"timeout"`
	Redirect     bool         `json:"followRedirect"`
	UserLevel    uint32       `json:"userLevel"`
}

type HTTPRemoteConfig struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type HTTPClientConfig struct {
	Servers []*HTTPRemoteConfig `json:"servers"`
	Headers map[string]string   `json:"headers"`
}

type ObservatoryConfig struct {
	SubjectSelector   []string          `json:"subjectSelector"`
	ProbeURL          string            `json:"probeURL"`
	ProbeInterval     duration.Duration `json:"probeInterval"`
	EnableConcurrency bool              `json:"enableConcurrency"`
}

type BurstObservatoryConfig struct {
	SubjectSelector []string `json:"subjectSelector"`
	// health check settings
	HealthCheck *healthCheckSettings `json:"pingConfig,omitempty"`
}


type MetricsConfig struct {
	Tag string `json:"tag"`
}

type Policy struct {
	Handshake         *uint32 `json:"handshake"`
	ConnectionIdle    *uint32 `json:"connIdle"`
	UplinkOnly        *uint32 `json:"uplinkOnly"`
	DownlinkOnly      *uint32 `json:"downlinkOnly"`
	StatsUserUplink   bool    `json:"statsUserUplink"`
	StatsUserDownlink bool    `json:"statsUserDownlink"`
	BufferSize        *int32  `json:"bufferSize"`
}

type SocksAccount struct {
	Username string `json:"user"`
	Password string `json:"pass"`
}


type SocksServerConfig struct {
	AuthMethod string          `json:"auth"`
	Accounts   []*SocksAccount `json:"accounts"`
	UDP        bool            `json:"udp"`
	Host       *Address        `json:"ip"`
	Timeout    uint32          `json:"timeout"`
	UserLevel  uint32          `json:"userLevel"`
}


type ShadowsocksUserConfig struct {
	Cipher   string   `json:"method"`
	Password string   `json:"password"`
	Level    byte     `json:"level"`
	Email    string   `json:"email"`
	Address  *Address `json:"address"`
	Port     uint16   `json:"port"`
}

type ShadowsocksServerConfig struct {
	Cipher      string                   `json:"method"`
	Password    string                   `json:"password"`
	Level       byte                     `json:"level"`
	Email       string                   `json:"email"`
	Users       []*ShadowsocksUserConfig `json:"clients"`
	NetworkList *NetworkList             `json:"network"`
	IVCheck     bool                     `json:"ivCheck"`
}

type ShadowsocksServerTarget struct {
	Address    *Address `json:"address"`
	Port       uint16   `json:"port"`
	Cipher     string   `json:"method"`
	Password   string   `json:"password"`
	Email      string   `json:"email"`
	Level      byte     `json:"level"`
	IVCheck    bool     `json:"ivCheck"`
	UoT        bool     `json:"uot"`
	UoTVersion int      `json:"uotVersion"`
}

type ShadowsocksClientConfig struct {
	Servers []*ShadowsocksServerTarget `json:"servers"`
}

type DNSOutboundConfig struct {
	Network    Network  `json:"network"`
	Address    *Address `json:"address"`
	Port       uint16   `json:"port"`
	UserLevel  uint32   `json:"userLevel"`
	NonIPQuery string   `json:"nonIPQuery"`
}

type LoopbackConfig struct {
	InboundTag string `json:"inboundTag"`
}


type BridgeConfig struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

type PortalConfig struct {
	Tag    string `json:"tag"`
	Domain string `json:"domain"`
}

type ReverseConfig struct {
	Bridges []BridgeConfig `json:"bridges"`
	Portals []PortalConfig `json:"portals"`
}

type WireGuardPeerConfig struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    uint32   `json:"keepAlive"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

type WireGuardConfig struct {
	IsClient bool `json:""`

	KernelMode     *bool                  `json:"kernelMode"`
	SecretKey      string                 `json:"secretKey"`
	Address        []string               `json:"address"`
	Peers          []*WireGuardPeerConfig `json:"peers"`
	MTU            int32                  `json:"mtu"`
	NumWorkers     int32                  `json:"workers"`
	Reserved       []byte                 `json:"reserved"`
	DomainStrategy string                 `json:"domainStrategy"`
}

type SocksRemoteConfig struct {
	Address *Address          `json:"address"`
	Port    uint16            `json:"port"`
	Users   []json.RawMessage `json:"users"`
}

type SocksClientConfig struct {
	Servers []*SocksRemoteConfig `json:"servers"`
	Version string               `json:"version"`
}

type TransportProtocol string



// healthCheckSettings holds settings for health Checker
type healthCheckSettings struct {
	Destination   string   `json:"destination"`
	Connectivity  string   `json:"connectivity"`
	Interval      duration.Duration `json:"interval"`
	SamplingCount int      `json:"sampling"`
	Timeout       duration.Duration `json:"timeout"`
}

// len(syscall.RawSockaddrUnix{}.Path)
const RawSockAddrUnixLen = 108
