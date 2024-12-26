package process

import (
	"time"
)

// ProcessInfo 进程基本信息
type ProcessInfo struct {
	PID         int     // 进程ID
	Name        string  // 进程名称
	Path        string  // 进程路径
	CommandLine string  // 命令行
	Owner       string  // 所有者
	CPU         float64 // CPU使用率
	Memory      uint64  // 内存使用量
	Status      string  // 进程状态
	StartTime   time.Time
	Threads     int32
	Handles     int32
}

// ProcessAnalyzer 进程分析器接口
type ProcessAnalyzer interface {
	// GetProcessList 获取进程列表
	GetProcessList() ([]ProcessInfo, error)
	// DetectSuspicious 检测可疑进程
	DetectSuspicious() ([]ProcessInfo, error)
}

// ProcessDetails 进程详细信息
type ProcessDetails struct {
	PID         int     // 进程ID
	Name        string  // 进程名称
	Path        string  // 进程路径
	CommandLine string  // 命令行
	Owner       string  // 所有者
	CPU         float64 // CPU使用率
	Memory      uint64  // 内存使用量
	Status      string  // 进程状态
	CreateTime  int64   // 创建时间
	NumThreads  int32   // 线程数
	ParentPID   int32   // 父进程ID
	Integrity   string  // 完整性级别
	IsElevated  bool    // 是否提升权限
}

// ProcessPermissions 进程权限信息
type ProcessPermissions struct {
	IsElevated  bool
	Integrity   string
	Privileges  []string
	IsProtected bool
}

// ProcessConnections 进程连接信息
type ProcessConnections struct {
	NetworkConns []NetworkConnection
	FileHandles  []string
}

// NetworkConnection 网络连接信息
type NetworkConnection struct {
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	Protocol   string
	State      string
}

// SecurityRisk 安全风险信息
type SecurityRisk struct {
	RiskLevel   string   // 风险级别：High, Medium, Low
	Description string   // 风险描述
	Details     string   // 详细信息
	Suggestions []string // 建议措施
}

// NewProcessAnalyzer 创建对应平台的进程分析器
func NewProcessAnalyzer() (ProcessAnalyzer, error) {
	return newWindowsProcessAnalyzer()
}
