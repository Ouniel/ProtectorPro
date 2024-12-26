package registry

import "time"

// RegistryItem 注册表项信息
type RegistryItem struct {
	Path     string
	Name     string
	Type     string
	Value    string
	Modified string
}

// AutoRun 自启动项信息
type AutoRun struct {
	Name        string
	Path        string
	Location    string
	IsEnabled   bool
	Publisher   string
	Description string
}

// AutoRunInfo 自启动项信息
type AutoRunInfo struct {
	Name        string
	Path        string
	Location    string
	Publisher   string
	Description string
	Modified    time.Time
}

// RegistryKey 注册表项信息
type RegistryKey struct {
	Path     string
	Name     string
	Type     string
	Value    string
	Modified time.Time
}

// SecuritySetting 安全设置信息
type SecuritySetting struct {
	Name        string
	Value       string
	Description string
	Risk        string
}

// RegistryAnalyzer 注册表分析器接口
type RegistryAnalyzer interface {
	// GetAutoRuns 获取自启动项
	GetAutoRuns() ([]AutoRunInfo, error)

	// DetectSuspicious 检测可疑注册表项
	DetectSuspicious() ([]RegistryKey, error)

	// AnalyzeSecuritySettings 分析系统安全设置
	AnalyzeSecuritySettings() ([]SecuritySetting, error)

	// GetAllRegistryKeys 获取所有注册表项
	GetAllRegistryKeys() ([]RegistryKey, error)
}

// NewRegistryAnalyzer 创建对应平台的注册表分析器
func NewRegistryAnalyzer() (RegistryAnalyzer, error) {
	return newWindowsRegistryAnalyzer()
}
