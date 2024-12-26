package network

// Connection 网络连接信息
type Connection struct {
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	Protocol    string
	State       string
	ProcessID   int
	ProcessName string
}

// NetworkAnalyzer 网络分析器接口
type NetworkAnalyzer interface {
	// GetConnections 获取所有网络连接
	GetConnections() ([]Connection, error)

	// DetectSuspicious 检测可疑连接
	DetectSuspicious() ([]Connection, error)

	// AnalyzeFirewallRules 分析防火墙规则
	AnalyzeFirewallRules() ([]string, error)
}

// NewNetworkAnalyzer 创建对应平台的网络分析器
func NewNetworkAnalyzer() (NetworkAnalyzer, error) {
	return newWindowsNetworkAnalyzer()
}
