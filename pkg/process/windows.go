//go:build windows
package process

import (
	"fmt"
	"strings"
	"time"
	"path/filepath"
	"os"
	"github.com/shirou/gopsutil/v3/process"
)

type windowsProcessAnalyzer struct{
	systemRoot string // Windows系统目录
}

func newWindowsProcessAnalyzer() (ProcessAnalyzer, error) {
	systemRoot := filepath.Clean(os.Getenv("SystemRoot"))
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	return &windowsProcessAnalyzer{
		systemRoot: systemRoot,
	}, nil
}

func (w *windowsProcessAnalyzer) GetProcessList() ([]ProcessInfo, error) {
	processes, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("获取进程列表失败: %v", err)
	}

	var result []ProcessInfo
	for _, p := range processes {
		info, err := w.getProcessInfo(p)
		if err != nil {
			continue // 跳过无法获取信息的进程
		}
		result = append(result, info)
	}

	return result, nil
}

func (w *windowsProcessAnalyzer) DetectSuspicious() ([]ProcessInfo, error) {
	processes, err := w.GetProcessList()
	if err != nil {
		return nil, err
	}

	var anomalous []ProcessInfo
	for _, p := range processes {
		if w.isAnomalousProcess(p) {
			anomalous = append(anomalous, p)
		}
	}

	return anomalous, nil
}

func (w *windowsProcessAnalyzer) getProcessInfo(p *process.Process) (ProcessInfo, error) {
	var info ProcessInfo

	// 获取基本信息
	info.PID = int(p.Pid)

	name, err := p.Name()
	if err == nil {
		info.Name = name
	}

	exe, err := p.Exe()
	if err == nil {
		info.Path = exe
	}

	cmdline, err := p.Cmdline()
	if err == nil {
		info.CommandLine = cmdline
	}

	username, err := p.Username()
	if err == nil {
		info.Owner = username
	}

	// 获取CPU使用率
	cpu, err := p.CPUPercent()
	if err == nil {
		info.CPU = cpu
	}

	// 获取内存使用
	memInfo, err := p.MemoryInfo()
	if err == nil && memInfo != nil {
		info.Memory = memInfo.RSS
	}

	// 获取进程状态
	status, err := p.Status()
	if err == nil && len(status) > 0 {
		info.Status = status[0]
	}

	// 获取启动时间
	createTime, err := p.CreateTime()
	if err == nil {
		info.StartTime = time.Unix(createTime/1000, 0)
	}

	// 获取线程数
	numThreads, err := p.NumThreads()
	if err == nil {
		info.Threads = numThreads
	}

	// 获取句柄数（Windows特有）
	info.Handles = 0

	return info, nil
}

// 内部辅助函数

// isAnomalousProcess 检测异常进程
// 返回true表示进程可能存在异常
func (w *windowsProcessAnalyzer) isAnomalousProcess(p ProcessInfo) bool {
	// 1. 检查系统进程位置
	if w.isSystemProcessInWrongLocation(p) {
		return true
	}

	// 2. 检查进程命令行
	if w.hasAnomalousCommandLine(p) {
		return true
	}

	// 3. 检查资源使用
	if w.hasAnomalousResourceUsage(p) {
		return true
	}

	// 4. 检查进程路径
	if w.isInNonStandardLocation(p) {
		return true
	}

	return false
}

// isSystemProcessInWrongLocation 检查系统进程是否在正确位置
func (w *windowsProcessAnalyzer) isSystemProcessInWrongLocation(p ProcessInfo) bool {
	systemProcs := map[string]string{
		"svchost.exe":   filepath.Join(w.systemRoot, "System32"),
		"lsass.exe":     filepath.Join(w.systemRoot, "System32"),
		"services.exe":  filepath.Join(w.systemRoot, "System32"),
		"winlogon.exe": filepath.Join(w.systemRoot, "System32"),
		"csrss.exe":    filepath.Join(w.systemRoot, "System32"),
		"smss.exe":     filepath.Join(w.systemRoot, "System32"),
		"wininit.exe":  filepath.Join(w.systemRoot, "System32"),
		"explorer.exe": w.systemRoot,
	}

	nameLower := strings.ToLower(p.Name)
	if expectedPath, ok := systemProcs[nameLower]; ok {
		actualPath := filepath.Clean(p.Path)
		expectedPath = filepath.Clean(expectedPath)
		
		if !strings.HasPrefix(strings.ToLower(actualPath), 
			strings.ToLower(expectedPath)) {
			return true
		}
	}

	return false
}

// hasAnomalousCommandLine 检查命令行是否异常
func (w *windowsProcessAnalyzer) hasAnomalousCommandLine(p ProcessInfo) bool {
	// 1. 检查隐藏行为
	hiddenBehaviors := []string{
		"-windowstyle hidden",
		"-w hidden",
		"-window hidden",
		"-noninteractive",
	}

	cmdLineLower := strings.ToLower(p.CommandLine)
	for _, behavior := range hiddenBehaviors {
		if strings.Contains(cmdLineLower, behavior) {
			return true
		}
	}

	// 2. 检查远程下载和执行
	remoteExecution := []string{
		"downloadstring",
		"downloadfile",
		"webclient",
		"invoke-webrequest",
		"start-bitstransfer",
	}

	for _, remote := range remoteExecution {
		if strings.Contains(cmdLineLower, remote) {
			return true
		}
	}

	// 3. 检查权限提升
	elevationAttempts := []string{
		"-exec bypass",
		"runas",
		"privilege::",
	}

	for _, elevation := range elevationAttempts {
		if strings.Contains(cmdLineLower, elevation) {
			return true
		}
	}

	return false
}

// hasAnomalousResourceUsage 检查资源使用是否异常
func (w *windowsProcessAnalyzer) hasAnomalousResourceUsage(p ProcessInfo) bool {
	// CPU使用率超过90%
	if p.CPU > 90.0 {
		return true
	}

	// 内存使用超过2GB
	if p.Memory > 2*1024*1024*1024 {
		return true
	}

	// 线程数异常（超过200个线程）
	if p.Threads > 200 {
		return true
	}

	return false
}

// isInNonStandardLocation 检查是否在非标准位置
func (w *windowsProcessAnalyzer) isInNonStandardLocation(p ProcessInfo) bool {
	nonStandardPaths := []string{
		"\\temp\\",
		"\\tmp\\",
		"\\downloads\\",
		"\\appdata\\local\\temp\\",
		"\\users\\public\\",
		"\\windows\\temp\\",
		"\\programdata\\temp\\",
	}

	execExtensions := []string{
		".exe", ".dll", ".bat", ".ps1", 
		".vbs", ".js", ".wsf", ".hta",
	}

	pathLower := strings.ToLower(p.Path)
	
	// 1. 检查是否在临时目录
	for _, path := range nonStandardPaths {
		if strings.Contains(pathLower, path) {
			// 2. 检查是否是可执行文件
			for _, ext := range execExtensions {
				if strings.HasSuffix(pathLower, ext) {
					return true
				}
			}
		}
	}

	// 3. 检查可执行文件是否来自标准程序目录
	standardPaths := []string{
		"\\program files\\",
		"\\program files (x86)\\",
		"\\windows\\",
		"\\windows\\system32\\",
	}

	isInStandardPath := false
	for _, path := range standardPaths {
		if strings.Contains(pathLower, path) {
			isInStandardPath = true
			break
		}
	}

	// 如果是可执行文件但不在标准路径中
	if !isInStandardPath {
		for _, ext := range execExtensions {
			if strings.HasSuffix(pathLower, ext) {
				return true
			}
		}
	}

	return false
}

func init() {
    registerProcessAnalyzer("windows", func() (ProcessAnalyzer, error) {
        return &windowsProcessAnalyzer{}, nil
    })
}
