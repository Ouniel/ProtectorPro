package export

import (
	"encoding/csv"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"ProtectorPro/pkg/eventlog"
	"ProtectorPro/pkg/network"
	"ProtectorPro/pkg/process"
	"ProtectorPro/pkg/registry"
	"ProtectorPro/pkg/system"
)

// ProcessesToCSV 导出进程信息到CSV文件
func ProcessesToCSV(processes []process.ProcessInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 根据操作系统选择不同的表头
	var headers []string
	if runtime.GOOS == "windows" {
		headers = []string{
			"PID", "Name", "Path", "CommandLine", "Owner",
			"Memory (KB)", "CPU %", "Status", "StartTime",
			"Threads", "Handles",
		}
	} else {
		headers = []string{
			"PID", "Name", "CommandLine", "Owner",
			"Memory (KB)", "CPU %", "Status", "StartTime",
		}
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, p := range processes {
		var row []string
		if runtime.GOOS == "windows" {
			row = []string{
				strconv.Itoa(p.PID),
				p.Name,
				p.Path,
				p.CommandLine,
				p.Owner,
				strconv.FormatUint(p.Memory/1024, 10),
				fmt.Sprintf("%.2f", p.CPU),
				p.Status,
				p.StartTime.Format(time.RFC3339),
				strconv.FormatInt(int64(p.Threads), 10),
				strconv.FormatInt(int64(p.Handles), 10),
			}
		} else {
			row = []string{
				strconv.Itoa(p.PID),
				p.Name,
				p.CommandLine,
				p.Owner,
				strconv.FormatUint(p.Memory/1024, 10),
				fmt.Sprintf("%.2f", p.CPU),
				p.Status,
				p.StartTime.Format(time.RFC3339),
			}
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

// ConnectionsToCSV 导出网络连接信息到CSV文件
func ConnectionsToCSV(connections []network.Connection, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"Local Address", "Local Port", "Remote Address", "Remote Port",
		"Protocol", "State", "Process ID", "Process Name",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, conn := range connections {
		row := []string{
			conn.LocalAddr,
			strconv.Itoa(conn.LocalPort),
			conn.RemoteAddr,
			strconv.Itoa(conn.RemotePort),
			conn.Protocol,
			conn.State,
			strconv.Itoa(conn.ProcessID),
			conn.ProcessName,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

// RegistryToCSV 导出注册表项信息到CSV文件
func RegistryToCSV(keys []registry.RegistryKey, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"Path", "Name", "Type", "Value", "Modified Time",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, key := range keys {
		row := []string{
			key.Path,
			key.Name,
			key.Type,
			key.Value,
			key.Modified.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

// EventLogsToCSV 将事件日志导出到CSV文件
func EventLogsToCSV(events []eventlog.SecurityEvent, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"Time", "Source", "Event ID", "Level",
		"Category", "Message", "Risk Level", "Analysis",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, event := range events {
		row := []string{
			event.Time.Format(time.RFC3339),
			event.Source,
			strconv.FormatInt(int64(event.EventID), 10),
			string(event.Level),
			string(event.EventType),
			event.Description,
			event.RiskLevel,
			event.Analysis,
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

// AutoRunsToCSV 导出自启动项信息到CSV文件
func AutoRunsToCSV(autoruns []registry.AutoRunInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"Name", "Path", "Location", "Publisher",
		"Description", "Modified Time",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, autorun := range autoruns {
		row := []string{
			autorun.Name,
			autorun.Path,
			autorun.Location,
			autorun.Publisher,
			autorun.Description,
			autorun.Modified.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

// SystemInfoToCSV 导出系统信息到CSV文件
func SystemInfoToCSV(info *system.SystemInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入基本信息
	headers := []string{"项目", "值"}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	rows := [][]string{
		{"主机名", info.Hostname},
		{"操作系统", info.OS},
		{"版本", info.Version},
		{"架构", info.Architecture},
		{"域", info.Domain},
		{"启动时间", info.BootTime.Format(time.RFC3339)},
		{"运行时间", info.Uptime.String()},
	}

	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	// 写入CPU信息
	if err := writer.Write([]string{"", ""}); err != nil {
		return fmt.Errorf("写入分隔符失败: %v", err)
	}
	if err := writer.Write([]string{"CPU信息", ""}); err != nil {
		return fmt.Errorf("写入CPU表头失败: %v", err)
	}

	for i, cpu := range info.CPUInfo {
		rows := [][]string{
			{fmt.Sprintf("CPU %d - 型号", i+1), cpu.Model},
			{fmt.Sprintf("CPU %d - 核心数", i+1), strconv.Itoa(cpu.Cores)},
			{fmt.Sprintf("CPU %d - 线程数", i+1), strconv.Itoa(cpu.Threads)},
			{fmt.Sprintf("CPU %d - 主频", i+1), fmt.Sprintf("%.2f GHz", cpu.ClockSpeed)},
			{fmt.Sprintf("CPU %d - 温度", i+1), fmt.Sprintf("%.1f °C", cpu.Temperature)},
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("写入CPU数据失败: %v", err)
			}
		}
	}

	// 写入内存信息
	if err := writer.Write([]string{"", ""}); err != nil {
		return fmt.Errorf("写入分隔符失败: %v", err)
	}
	if err := writer.Write([]string{"内存信息", ""}); err != nil {
		return fmt.Errorf("写入内存表头失败: %v", err)
	}

	memRows := [][]string{
		{"总内存", formatBytes(info.MemoryInfo.Total)},
		{"可用内存", formatBytes(info.MemoryInfo.Available)},
		{"已用内存", formatBytes(info.MemoryInfo.Used)},
		{"交换总量", formatBytes(info.MemoryInfo.SwapTotal)},
		{"已用交换", formatBytes(info.MemoryInfo.SwapUsed)},
	}

	for _, row := range memRows {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入内存数据失败: %v", err)
		}
	}

	// 写入磁盘信息
	if err := writer.Write([]string{"", ""}); err != nil {
		return fmt.Errorf("写入分隔符失败: %v", err)
	}
	if err := writer.Write([]string{"磁盘信息", ""}); err != nil {
		return fmt.Errorf("写入磁盘表头失败: %v", err)
	}

	for _, disk := range info.DiskInfo {
		rows := [][]string{
			{fmt.Sprintf("设备 %s - 挂载点", disk.Device), disk.MountPoint},
			{fmt.Sprintf("设备 %s - 文件系统", disk.Device), disk.FileSystem},
			{fmt.Sprintf("设备 %s - 总容量", disk.Device), formatBytes(disk.Total)},
			{fmt.Sprintf("设备 %s - 已用空间", disk.Device), formatBytes(disk.Used)},
			{fmt.Sprintf("设备 %s - 可用空间", disk.Device), formatBytes(disk.Available)},
		}
		for _, row := range rows {
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("写入磁盘数据失败: %v", err)
			}
		}
	}

	return nil
}

// UsersToCSV 导出用户信息到CSV文件
func UsersToCSV(users []system.UserInfo, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入表头
	headers := []string{
		"用户名", "全名", "主目录", "最后登录时间",
		"用户组", "特权", "管理员", "已禁用", "已锁定",
		"最后密码修改时间",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入表头失败: %v", err)
	}

	// 写入数据
	for _, user := range users {
		row := []string{
			user.Username,
			user.FullName,
			user.HomeDir,
			user.LastLogin.Format(time.RFC3339),
			strings.Join(user.Groups, ";"),
			strings.Join(user.Privileges, ";"),
			strconv.FormatBool(user.IsAdmin),
			strconv.FormatBool(user.IsDisabled),
			strconv.FormatBool(user.IsLocked),
			user.LastPasswdChange.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("写入数据失败: %v", err)
		}
	}

	return nil
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
