package analyzer

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"ProtectorPro/pkg/eventlog"
	"ProtectorPro/pkg/export"
	"ProtectorPro/pkg/network"
	"ProtectorPro/pkg/process"
	"ProtectorPro/pkg/registry"
	"ProtectorPro/pkg/rules"
	"ProtectorPro/pkg/system"
)

// SecurityAnalyzer 安全分析器接口
type SecurityAnalyzer interface {
	// AnalyzeSystem 分析系统信息
	AnalyzeSystem(outputDir string, timestamp string) error
	// AnalyzeProcesses 分析进程
	AnalyzeProcesses(outputDir string, timestamp string) error
	// AnalyzeNetwork 分析网络
	AnalyzeNetwork(outputDir string, timestamp string) error
	// AnalyzeRegistry 分析注册表
	AnalyzeRegistry(outputDir string, timestamp string) error
	// AnalyzeEventLogs 分析事件日志
	AnalyzeEventLogs(outputDir string, timestamp string) error
}

// Analyzer 实现SecurityAnalyzer接口
type Analyzer struct {
	ruleEngine *rules.RuleEngine
}

// NewAnalyzer 创建新的安全分析器
func NewAnalyzer(ruleEngine *rules.RuleEngine) *Analyzer {
	return &Analyzer{
		ruleEngine: ruleEngine,
	}
}

// AnalyzeSystem 分析系统信息
func (a *Analyzer) AnalyzeSystem(outputDir string, timestamp string) error {
	analyzer, err := system.NewSystemAnalyzer()
	if err != nil {
		return fmt.Errorf("创建系统分析器失败: %v", err)
	}

	// 获取系统信息
	sysInfo, err := analyzer.GetSystemInfo()
	if err != nil {
		log.Printf("获取系统信息失败: %v", err)
	} else {
		// 导出系统信息
		filename := filepath.Join(outputDir, fmt.Sprintf("system_info_%s.csv", timestamp))
		if err := export.SystemInfoToCSV(sysInfo, filename); err != nil {
			log.Printf("导出系统信息失败: %v", err)
		} else {
			log.Printf("系统信息已导出到: %s", filename)
		}

		// 应用系统规则
		data := map[string]interface{}{
			"memory_usage":  float64(sysInfo.MemoryInfo.Used) / float64(sysInfo.MemoryInfo.Total) * 100,
			"cpu_usage":     getCPUUsage(sysInfo.CPUInfo),
			"disk_free":     getDiskFreePercentage(sysInfo.DiskInfo),
		}

		for _, rule := range a.ruleEngine.Rules {
			if rule.Category == "system" && a.ruleEngine.EvaluateRule(rule, data) {
				log.Printf("检测到系统异常 [%s]: %s", rule.ID, rule.Description)
			}
		}
	}

	// 获取所有用户
	users, err := analyzer.GetUsers()
	if err != nil {
		log.Printf("获取用户列表失败: %v", err)
	} else {
		// 导出用户信息
		filename := filepath.Join(outputDir, fmt.Sprintf("users_all_%s.csv", timestamp))
		if err := export.UsersToCSV(users, filename); err != nil {
			log.Printf("导出用户信息失败: %v", err)
		} else {
			log.Printf("用户信息已导出到: %s", filename)
		}

		// 应用用户规则
		for _, user := range users {
			data := map[string]interface{}{
				"username":        user.Username,
				"is_admin":        user.IsAdmin,
				"is_disabled":     user.IsDisabled,
				"is_locked":       user.IsLocked,
				"last_login_time": user.LastLogin.Format(time.RFC3339),
				"groups":          user.Groups,
			}

			for _, rule := range a.ruleEngine.Rules {
				if rule.Category == "user" && a.ruleEngine.EvaluateRule(rule, data) {
					log.Printf("检测到可疑用户 [%s]: %s - %s", rule.ID, user.Username, rule.Description)
				}
			}
		}
	}

	return nil
}

// AnalyzeProcesses 分析进程
func (a *Analyzer) AnalyzeProcesses(outputDir string, timestamp string) error {
	analyzer, err := process.NewProcessAnalyzer()
	if err != nil {
		return fmt.Errorf("创建进程分析器失败: %v", err)
	}

	// 获取所有进程
	processes, err := analyzer.GetProcessList()
	if err != nil {
		log.Printf("获取进程列表失败: %v", err)
	} else {
		// 导出进程信息
		filename := filepath.Join(outputDir, fmt.Sprintf("processes_all_%s.csv", timestamp))
		if err := export.ProcessesToCSV(processes, filename); err != nil {
			log.Printf("导出进程信息失败: %v", err)
		} else {
			log.Printf("进程信息已导出到: %s", filename)
		}

		// 应用进程规则
		for _, proc := range processes {
			data := map[string]interface{}{
				"name":       proc.Name,
				"pid":        proc.PID,
				"path":       proc.Path,
				"command":    proc.CommandLine,
				"cpu":        proc.CPU,
				"memory":     proc.Memory,
				"status":     proc.Status,
				"start_time": proc.StartTime.Format(time.RFC3339),
				"threads":    proc.Threads,
				"handles":    proc.Handles,
			}

			for _, rule := range a.ruleEngine.Rules {
				if rule.Category == "process" && a.ruleEngine.EvaluateRule(rule, data) {
					log.Printf("检测到可疑进程 [%s]: %s (PID: %d) - %s",
						rule.ID, proc.Name, proc.PID, rule.Description)
				}
			}
		}
	}

	return nil
}

// AnalyzeNetwork 分析网络
func (a *Analyzer) AnalyzeNetwork(outputDir string, timestamp string) error {
	analyzer, err := network.NewNetworkAnalyzer()
	if err != nil {
		return fmt.Errorf("创建网络分析器失败: %v", err)
	}

	// 获取所有网络连接
	connections, err := analyzer.GetConnections()
	if err != nil {
		log.Printf("获取网络连接失败: %v", err)
	} else {
		// 导出网络连接信息
		filename := filepath.Join(outputDir, fmt.Sprintf("connections_all_%s.csv", timestamp))
		if err := export.ConnectionsToCSV(connections, filename); err != nil {
			log.Printf("导出网络连接失败: %v", err)
		} else {
			log.Printf("网络连接已导出到: %s", filename)
		}

		// 应用网络规则
		for _, conn := range connections {
			data := map[string]interface{}{
				"local_addr":   conn.LocalAddr,
				"local_port":   conn.LocalPort,
				"remote_addr":  conn.RemoteAddr,
				"remote_port":  conn.RemotePort,
				"state":        conn.State,
				"process_name": conn.ProcessName,
				"process_id":   conn.ProcessID,
			}

			for _, rule := range a.ruleEngine.Rules {
				if rule.Category == "network" && a.ruleEngine.EvaluateRule(rule, data) {
					log.Printf("检测到可疑网络连接 [%s]: %s:%d -> %s:%d (%s) - %s",
						rule.ID, conn.LocalAddr, conn.LocalPort,
						conn.RemoteAddr, conn.RemotePort,
						conn.ProcessName, rule.Description)
				}
			}
		}
	}

	return nil
}

// AnalyzeRegistry 分析注册表
func (a *Analyzer) AnalyzeRegistry(outputDir string, timestamp string) error {
	analyzer, err := registry.NewRegistryAnalyzer()
	if err != nil {
		return fmt.Errorf("创建注册表分析器失败: %v", err)
	}

	// 获取所有注册表项
	keys, err := analyzer.GetAllRegistryKeys()
	if err != nil {
		log.Printf("获取注册表项失败: %v", err)
	} else {
		// 导出注册表信息
		filename := filepath.Join(outputDir, fmt.Sprintf("registry_all_%s.csv", timestamp))
		if err := export.RegistryToCSV(keys, filename); err != nil {
			log.Printf("导出注册表信息失败: %v", err)
		} else {
			log.Printf("注册表信息已导出到: %s", filename)
		}

		// 应用注册表规则
		for _, key := range keys {
			data := map[string]interface{}{
				"path":          key.Path,
				"name":          key.Name,
				"value":         key.Value,
				"value_type":    key.Type,
				"modified_time": key.Modified.Format(time.RFC3339),
			}

			for _, rule := range a.ruleEngine.Rules {
				if rule.Category == "registry" && a.ruleEngine.EvaluateRule(rule, data) {
					log.Printf("检测到可疑注册表项 [%s]: %s\\%s - %s",
						rule.ID, key.Path, key.Name, rule.Description)
				}
			}
		}
	}

	return nil
}

// AnalyzeEventLogs 分析事件日志
func (a *Analyzer) AnalyzeEventLogs(outputDir string, timestamp string) error {
	analyzer, err := eventlog.NewEventLogAnalyzer()
	if err != nil {
		// 如果是权限问题，给出更友好的提示
		if strings.Contains(err.Error(), "需要管理员权限") {
			log.Printf("警告: %v", err)
			log.Printf("提示: 请右键点击程序，选择'以管理员身份运行'来获取完整的安全评估结果")
			return nil  // 继续执行其他分析
		}
		return fmt.Errorf("创建事件日志分析器失败: %v", err)
	}

	// 获取过去24小时的时间
	startTime := time.Now().Add(-24 * time.Hour)

	// 获取所有事件
	allEvents, err := analyzer.GetAllEvents(startTime)
	if err != nil {
		return fmt.Errorf("获取事件日志失败: %v", err)
	}

	// 导出所有事件日志
	allEventsFile := filepath.Join(outputDir, fmt.Sprintf("all_event_logs_%s.csv", timestamp))
	if err := export.EventLogsToCSV(allEvents, allEventsFile); err != nil {
		return fmt.Errorf("导出所有事件日志失败: %v", err)
	}
	log.Printf("已导出 %d 条所有事件日志到: %s", len(allEvents), allEventsFile)

	// 根据规则筛选事件
	var filteredEvents []eventlog.SecurityEvent
	for _, event := range allEvents {
		// 检查每个规则
		for _, rule := range a.ruleEngine.Rules {
			// 检查规则是否适用于事件日志
			if rule.Category != "eventlog" {
				continue
			}

			// 检查每个条件
			for _, condition := range rule.Conditions {
				// 解析事件ID条件，格式如: "event_id=4624"
				if strings.HasPrefix(condition, "event_id=") {
					eventIDStr := strings.TrimPrefix(condition, "event_id=")
					var eventID uint32
					fmt.Sscanf(eventIDStr, "%d", &eventID)
					
					// 比较事件ID
					if eventID == event.EventID {
						filteredEvents = append(filteredEvents, event)
						// 找到匹配的规则，记录警告信息
						log.Printf("检测到可疑事件 [%s]: EventID=%d, Time=%s, User=%s - %s",
							rule.ID, event.EventID, event.Time.Format("2006-01-02 15:04:05"),
							event.User, rule.Description)
						break // 跳出条件循环
					}
				}
			}
		}
	}

	// 导出筛选后的事件日志
	filteredEventsFile := filepath.Join(outputDir, fmt.Sprintf("filtered_event_logs_%s.csv", timestamp))
	if err := export.EventLogsToCSV(filteredEvents, filteredEventsFile); err != nil {
		return fmt.Errorf("导出筛选后的事件日志失败: %v", err)
	}
	log.Printf("已导出 %d 条筛选后的事件日志到: %s", len(filteredEvents), filteredEventsFile)

	return nil
}

// 辅助函数

func getCPUUsage(cpuInfo []system.CPUInfo) float64 {
	if len(cpuInfo) == 0 {
		return 0
	}

	var totalUsage float64
	for _, cpu := range cpuInfo {
		totalUsage += cpu.Usage
	}
	return totalUsage / float64(len(cpuInfo))
}

func getDiskFreePercentage(diskInfo []system.DiskInfo) float64 {
	if len(diskInfo) == 0 {
		return 100
	}

	var totalSpace, totalFree uint64
	for _, disk := range diskInfo {
		totalSpace += disk.Total
		totalFree += disk.Available
	}

	if totalSpace == 0 {
		return 100
	}

	return float64(totalFree) / float64(totalSpace) * 100
}
