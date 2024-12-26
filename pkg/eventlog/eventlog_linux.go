//go:build linux
package eventlog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Linux 系统日志文件路径
const (
	authLogPath     = "/var/log/auth.log"
	syslogPath      = "/var/log/syslog"
	securityLogPath = "/var/log/secure"
	auditLogPath    = "/var/log/audit/audit.log"
)

type linuxEventLogAnalyzer struct {
	logPaths map[string]string
}

func init() {
	// 在 init 函数中注册 Linux 的初始化函数
	registerEventLogAnalyzer("linux", func() (EventLogAnalyzer, error) {
		return &linuxEventLogAnalyzer{
			logPaths: map[string]string{
				"auth"     : authLogPath,
				"syslog"   : syslogPath,
				"security": securityLogPath,
				"audit"    : auditLogPath,
			},
		}, nil
	})
}

// readLogFilesSince 从指定时间开始读取日志文件
func (l *linuxEventLogAnalyzer) readLogFilesSince(logPath string, since time.Time) ([]string, error) {
	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// 解析日志时间戳
		if timestamp, err := time.Parse(time.RFC3339, strings.Split(line, " ")[0]); err == nil {
			if timestamp.After(since) {
				lines = append(lines, line)
			}
		}
	}
	return lines, scanner.Err()
}

// GetLoginEvents 获取登录事件
func (l *linuxEventLogAnalyzer) GetLoginEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["auth"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "sshd") || strings.Contains(line, "login") {
			// 解析登录事件
			event := SecurityEvent{
				EventType:   EventTypeLogin,
				Source:     "auth",
				Time:       time.Now(), // 需要从日志行解析实际时间
				Level:      EventLevelInformation,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetPrivilegeEvents 获取权限事件
func (l *linuxEventLogAnalyzer) GetPrivilegeEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["auth"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "sudo") {
			event := SecurityEvent{
				EventType:   EventTypePrivilege,
				Source:     "auth",
				Time:       time.Now(),
				Level:      EventLevelWarning,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetProcessEvents 获取进程事件
func (l *linuxEventLogAnalyzer) GetProcessEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["audit"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "SYSCALL") || strings.Contains(line, "EXECVE") {
			event := SecurityEvent{
				EventType:   EventTypeProcess,
				Source:     "audit",
				Time:       time.Now(),
				Level:      EventLevelInformation,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetAuditEvents 获取审计事件
func (l *linuxEventLogAnalyzer) GetAuditEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["audit"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "CONFIG_CHANGE") {
			event := SecurityEvent{
				EventType:   EventTypeAudit,
				Source:     "audit",
				Time:       time.Now(),
				Level:      EventLevelWarning,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetUserAccountEvents 获取用户账户事件
func (l *linuxEventLogAnalyzer) GetUserAccountEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["auth"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "useradd") || strings.Contains(line, "usermod") || strings.Contains(line, "userdel") {
			event := SecurityEvent{
				EventType:   EventTypeUserAccount,
				Source:     "auth",
				Time:       time.Now(),
				Level:      EventLevelWarning,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetGroupPolicyEvents 获取组策略事件
func (l *linuxEventLogAnalyzer) GetGroupPolicyEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["auth"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "groupadd") || strings.Contains(line, "groupmod") || strings.Contains(line, "groupdel") {
			event := SecurityEvent{
				EventType:   EventTypeGroupPolicy,
				Source:     "auth",
				Time:       time.Now(),
				Level:      EventLevelWarning,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetServiceEvents 获取服务事件
func (l *linuxEventLogAnalyzer) GetServiceEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["syslog"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "systemd") || strings.Contains(line, "service") {
			event := SecurityEvent{
				EventType:   EventTypeService,
				Source:     "syslog",
				Time:       time.Now(),
				Level:      EventLevelInformation,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}

// GetFirewallEvents 获取防火墙事件
func (l *linuxEventLogAnalyzer) GetFirewallEvents(since time.Time) ([]SecurityEvent, error) {
	events := make([]SecurityEvent, 0)
	lines, err := l.readLogFilesSince(l.logPaths["syslog"], since)
	if err != nil {
		return nil, err
	}

	for _, line := range lines {
		if strings.Contains(line, "iptables") || strings.Contains(line, "firewalld") {
			event := SecurityEvent{
				EventType:   EventTypeFirewall,
				Source:     "syslog",
				Time:       time.Now(),
				Level:      EventLevelWarning,
				Description: line,
			}
			events = append(events, event)
		}
	}
	return events, nil
}
