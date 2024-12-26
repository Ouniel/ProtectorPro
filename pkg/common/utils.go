package common

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Report 安全分析报告结构
type Report struct {
	Timestamp     time.Time       `json:"timestamp"`
	SystemInfo    SystemInfo      `json:"system_info"`
	ProcessInfo   []ProcessReport `json:"process_info"`
	NetworkInfo   []NetworkReport `json:"network_info"`
	SecurityScore float64         `json:"security_score"`
	Warnings      []Warning       `json:"warnings"`
}

// SystemInfo 系统信息
type SystemInfo struct {
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	Hostname      string `json:"hostname"`
	KernelVersion string `json:"kernel_version"`
}

// ProcessReport 进程分析报告
type ProcessReport struct {
	PID          int      `json:"pid"`
	Name         string   `json:"name"`
	Risk         float64  `json:"risk_score"`
	Warnings     []string `json:"warnings"`
	Permissions  []string `json:"permissions"`
}

// NetworkReport 网络分析报告
type NetworkReport struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr"`
	State       string `json:"state"`
	ProcessName string `json:"process_name"`
	Risk        float64 `json:"risk_score"`
}

// Warning 警告信息
type Warning struct {
	Level       string    `json:"level"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
}

// SaveReport 保存报告到文件
func SaveReport(report *Report, filepath string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %v", err)
	}

	err = os.WriteFile(filepath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report to file: %v", err)
	}

	return nil
}

// CalculateRiskScore 计算风险评分
func CalculateRiskScore(warnings []Warning) float64 {
	var score float64
	for _, warning := range warnings {
		switch warning.Level {
		case "critical":
			score += 10.0
		case "high":
			score += 7.0
		case "medium":
			score += 4.0
		case "low":
			score += 1.0
		}
	}
	// 将分数标准化到0-100范围
	return score
}
