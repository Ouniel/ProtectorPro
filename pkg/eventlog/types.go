package eventlog

import "time"

// EventType 事件类型
type EventType string

const (
	EventTypeLogin       EventType = "LOGIN"
	EventTypePrivilege   EventType = "PRIVILEGE"
	EventTypeProcess     EventType = "PROCESS"
	EventTypeAudit       EventType = "AUDIT"
	EventTypeUserAccount EventType = "USER_ACCOUNT"
	EventTypeGroupPolicy EventType = "GROUP_POLICY"
	EventTypeService     EventType = "SERVICE"
	EventTypeFirewall    EventType = "FIREWALL"
	EventTypeOther       EventType = "OTHER"  // 添加其他类型
)

// EventLevel 事件级别
type EventLevel string

const (
	EventLevelError       EventLevel = "Error"
	EventLevelWarning     EventLevel = "Warning"
	EventLevelInformation EventLevel = "Information"
	EventLevelSuccess     EventLevel = "Success"
)

// EventLogEntry 表示一个事件日志条目
type EventLogEntry struct {
	TimeGenerated time.Time // 事件生成时间
	Source        string    // 事件来源
	EventID       int       // 事件ID
	Level         string    // 事件级别
	Category      string    // 事件类别
	Message       string    // 事件消息
	Computer      string    // 计算机名
	UserName      string    // 用户名
}

// SecurityEvent 表示一个安全事件
type SecurityEvent struct {
	EventID      uint32      // 事件ID
	EventType    EventType   // 事件类型
	Source       string      // 事件源
	Time         time.Time   // 事件时间
	Level        EventLevel  // 事件级别
	Description  string      // 事件描述
	User         string      // 相关用户
	Computer     string      // 计算机名
	ProcessName  string      // 进程名
	ProcessID    uint32      // 进程ID
	Category     string      // 事件类别
	Result       string      // 事件结果
	RawData      []byte     // 原始数据
	RiskLevel    string     // 风险级别：High, Medium, Low
	Analysis     string     // 分析结果
}

// EventLogAnalyzer 事件日志分析器接口
type EventLogAnalyzer interface {
	// GetAllEvents 获取所有事件
	GetAllEvents(since time.Time) ([]SecurityEvent, error)
	
	// GetLoginEvents 获取登录事件
	GetLoginEvents(since time.Time) ([]SecurityEvent, error)

	// GetPrivilegeEvents 获取特权使用事件
	GetPrivilegeEvents(since time.Time) ([]SecurityEvent, error)

	// GetProcessEvents 获取进程事件
	GetProcessEvents(since time.Time) ([]SecurityEvent, error)

	// GetAuditEvents 获取审计事件
	GetAuditEvents(since time.Time) ([]SecurityEvent, error)

	// GetUserAccountEvents 获取用户账户事件
	GetUserAccountEvents(since time.Time) ([]SecurityEvent, error)

	// GetGroupPolicyEvents 获取组策略事件
	GetGroupPolicyEvents(since time.Time) ([]SecurityEvent, error)

	// GetServiceEvents 获取服务事件
	GetServiceEvents(since time.Time) ([]SecurityEvent, error)

	// GetFirewallEvents 获取防火墙事件
	GetFirewallEvents(since time.Time) ([]SecurityEvent, error)

	// Close 关闭分析器
	Close() error
}
