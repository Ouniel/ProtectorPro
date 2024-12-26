//go:build windows
package network

import (
	"fmt"
	"net"
	"strings"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

type windowsNetworkAnalyzer struct{}

func newWindowsNetworkAnalyzer() (NetworkAnalyzer, error) {
	return &windowsNetworkAnalyzer{}, nil
}

func (w *windowsNetworkAnalyzer) GetConnections() ([]Connection, error) {
	// 获取所有网络连接
	connections, err := psnet.Connections("all")
	if err != nil {
		return nil, fmt.Errorf("获取网络连接失败: %v", err)
	}

	var result []Connection
	for _, conn := range connections {
		// 获取进程信息
		var procName string
		if conn.Pid > 0 {
			if p, err := process.NewProcess(conn.Pid); err == nil {
				if name, err := p.Name(); err == nil {
					procName = name
				}
			}
		}

		// 构建连接信息
		connInfo := Connection{
			LocalAddr:   conn.Laddr.IP,
			LocalPort:   int(conn.Laddr.Port),
			RemoteAddr:  conn.Raddr.IP,
			RemotePort:  int(conn.Raddr.Port),
			Protocol:    getProtocolName(conn.Type),
			State:      conn.Status,
			ProcessID:   int(conn.Pid),
			ProcessName: procName,
		}
		result = append(result, connInfo)
	}

	return result, nil
}

func (w *windowsNetworkAnalyzer) DetectSuspicious() ([]Connection, error) {
	connections, err := w.GetConnections()
	if err != nil {
		return nil, err
	}

	var suspicious []Connection
	for _, conn := range connections {
		if isSuspiciousConnection(conn) {
			suspicious = append(suspicious, conn)
		}
	}

	return suspicious, nil
}

func (w *windowsNetworkAnalyzer) AnalyzeFirewallRules() ([]string, error) {
	// 使用 netsh 命令获取防火墙规则
	// 这里返回一个示例
	return []string{
		"允许入站: TCP 80 (HTTP)",
		"允许入站: TCP 443 (HTTPS)",
		"阻止入站: TCP 3389 (RDP)",
	}, nil
}

// 内部辅助函数

func getProtocolName(protocolType uint32) string {
	switch protocolType {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", protocolType)
	}
}

func isSuspiciousConnection(conn Connection) bool {
	// 检查可疑端口
	suspiciousPorts := map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		445:   "SMB",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		4444:  "Metasploit",
		5900:  "VNC",
		6667:  "IRC",
		8080:  "HTTP Proxy",
		9001:  "Tor",
		31337: "Back Orifice",
	}

	if _, ok := suspiciousPorts[conn.RemotePort]; ok {
		return true
	}

	// 检查可疑进程
	suspiciousProcesses := []string{
		"nc.exe",
		"ncat.exe",
		"netcat.exe",
		"psexec.exe",
		"at.exe",
		"telnet.exe",
		"ftp.exe",
	}

	procNameLower := strings.ToLower(conn.ProcessName)
	for _, name := range suspiciousProcesses {
		if strings.Contains(procNameLower, strings.ToLower(name)) {
			return true
		}
	}

	// 检查可疑远程地址
	if isPrivateIP(conn.RemoteAddr) {
		return false
	}

	// 检查连接状态
	if conn.State == "LISTEN" && conn.RemotePort == 0 {
		return false // 正常的监听端口
	}

	// 检查是否为已建立的出站连接
	if conn.State == "ESTABLISHED" && conn.RemotePort > 1024 {
		return false // 正常的出站连接
	}

	return false
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// 检查是否为私有IP地址范围
	privateIPBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, block := range privateIPBlocks {
		_, ipnet, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}

	return false
}

func init() {
    registerNetworkAnalyzer("windows", func() (NetworkAnalyzer, error) {
        return &windowsNetworkAnalyzer{}, nil
    })
}
