package system

import (
	"time"
)

// SystemInfo 系统信息
type SystemInfo struct {
	Hostname     string
	OS           string
	Version      string
	Architecture string
	Domain       string
	Uptime       time.Duration
	BootTime     time.Time
	CPUInfo      []CPUInfo
	MemoryInfo   MemoryInfo
	DiskInfo     []DiskInfo
}

// CPUInfo CPU信息
type CPUInfo struct {
	Model       string
	Cores       int
	Threads     int
	ClockSpeed  float64
	Temperature float64
	Usage       float64  // CPU使用率(百分比)
}

// MemoryInfo 内存信息
type MemoryInfo struct {
	Total     uint64
	Available uint64
	Used      uint64
	SwapTotal uint64
	SwapUsed  uint64
}

// DiskInfo 磁盘信息
type DiskInfo struct {
	Device     string
	MountPoint string
	FileSystem string
	Total      uint64
	Used       uint64
	Available  uint64
}

// UserInfo 用户信息
type UserInfo struct {
	Username    string
	FullName    string
	HomeDir     string
	LastLogin   time.Time
	Groups      []string
	Privileges  []string
	IsAdmin     bool
	IsDisabled  bool
	IsLocked    bool
	LastPasswdChange time.Time
}

// SystemAnalyzer 系统分析器接口
type SystemAnalyzer interface {
	// GetSystemInfo 获取系统信息
	GetSystemInfo() (*SystemInfo, error)
	// GetUsers 获取用户列表
	GetUsers() ([]UserInfo, error)
	// DetectSuspiciousUsers 检测可疑用户
	DetectSuspiciousUsers() ([]UserInfo, error)
}

// NewSystemAnalyzer 创建对应平台的系统分析器
func NewSystemAnalyzer() (SystemAnalyzer, error) {
	return newSystemAnalyzer()
}
