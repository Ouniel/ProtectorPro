//go:build windows
package registry

import (
	"fmt"
	"os"
	"strings"
	"time"
	"golang.org/x/sys/windows/registry"
)

type windowsRegistryAnalyzer struct{}

func newWindowsRegistryAnalyzer() (RegistryAnalyzer, error) {
	return &windowsRegistryAnalyzer{}, nil
}

func (w *windowsRegistryAnalyzer) GetAutoRuns() ([]AutoRunInfo, error) {
	var autoruns []AutoRunInfo

	// 检查常见的自启动注册表项
	autorunKeys := []struct {
		path string
		key  registry.Key
	}{
		{"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", registry.LOCAL_MACHINE},
		{"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", registry.LOCAL_MACHINE},
		{"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", registry.CURRENT_USER},
		{"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", registry.CURRENT_USER},
	}

	for _, ak := range autorunKeys {
		k, err := registry.OpenKey(ak.key, strings.TrimPrefix(ak.path, "HKEY_LOCAL_MACHINE\\"), registry.READ)
		if err != nil {
			k, err = registry.OpenKey(ak.key, strings.TrimPrefix(ak.path, "HKEY_CURRENT_USER\\"), registry.READ)
			if err != nil {
				continue
			}
		}
		defer k.Close()

		names, err := k.ReadValueNames(-1)
		if err != nil {
			continue
		}

		for _, name := range names {
			value, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}

			// 获取文件信息
			path := value
			if strings.HasPrefix(path, "\"") {
				path = strings.Trim(path, "\"")
			}
			parts := strings.Split(path, " ")
			if len(parts) > 0 {
				path = parts[0]
			}

			info := AutoRunInfo{
				Name:     name,
				Path:     path,
				Location: ak.path,
			}

			// 尝试获取文件属性
			if fi, err := os.Stat(path); err == nil {
				info.Modified = fi.ModTime()
			}

			autoruns = append(autoruns, info)
		}
	}

	return autoruns, nil
}

func (w *windowsRegistryAnalyzer) DetectSuspicious() ([]RegistryKey, error) {
	var suspicious []RegistryKey

	// 检查可疑的注册表路径
	suspiciousPaths := []struct {
		path string
		key  registry.Key
	}{
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", registry.LOCAL_MACHINE},
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", registry.LOCAL_MACHINE},
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", registry.LOCAL_MACHINE},
		{"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs", registry.LOCAL_MACHINE},
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders", registry.LOCAL_MACHINE},
		{"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders", registry.LOCAL_MACHINE},
		{"SYSTEM\\CurrentControlSet\\Services", registry.LOCAL_MACHINE},
	}

	for _, sp := range suspiciousPaths {
		k, err := registry.OpenKey(sp.key, sp.path, registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()

		names, err := k.ReadValueNames(-1)
		if err != nil {
			continue
		}

		for _, name := range names {
			value, valType, err := k.GetStringValue(name)
			if err != nil {
				continue
			}

			if isSuspiciousRegistryValue(value) {
				key := RegistryKey{
					Path:  sp.path,
					Name:  name,
					Type:  getRegistryValueTypeName(valType),
					Value: value,
				}

				// 尝试获取最后修改时间
				if stat, err := k.Stat(); err == nil {
					key.Modified = time.Unix(0, stat.ModTime().UnixNano())
				}

				suspicious = append(suspicious, key)
			}
		}
	}

	return suspicious, nil
}

func (w *windowsRegistryAnalyzer) AnalyzeSecuritySettings() ([]SecuritySetting, error) {
	var settings []SecuritySetting

	// 检查重要的安全设置
	securityPaths := []struct {
		path        string
		key         registry.Key
		valueName   string
		settingName string
		description string
	}{
		{
			"SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
			registry.LOCAL_MACHINE,
			"fDenyTSConnections",
			"远程桌面访问",
			"控制是否允许远程桌面连接",
		},
		{
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
			registry.LOCAL_MACHINE,
			"EnableLUA",
			"用户账户控制(UAC)",
			"控制是否启用用户账户控制",
		},
		{
			"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
			registry.LOCAL_MACHINE,
			"EnableFirewall",
			"Windows 防火墙",
			"控制是否启用Windows防火墙",
		},
		{
			"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update",
			registry.LOCAL_MACHINE,
			"AUOptions",
			"Windows 自动更新",
			"控制Windows更新的自动更新设置",
		},
	}

	for _, sp := range securityPaths {
		k, err := registry.OpenKey(sp.key, sp.path, registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()

		value, _, err := k.GetIntegerValue(sp.valueName)
		if err != nil {
			continue
		}

		setting := SecuritySetting{
			Name:        sp.settingName,
			Value:       fmt.Sprintf("%d", value),
			Description: sp.description,
		}

		// 根据不同设置判断风险等级
		switch sp.valueName {
		case "fDenyTSConnections":
			if value == 0 {
				setting.Risk = "高"
				setting.Description += "。当前设置允许远程连接，可能存在安全风险"
			} else {
				setting.Risk = "低"
				setting.Description += "。当前设置禁止远程连接"
			}
		case "EnableLUA":
			if value == 0 {
				setting.Risk = "高"
				setting.Description += "。UAC已禁用，系统容易受到恶意软件攻击"
			} else {
				setting.Risk = "低"
				setting.Description += "。UAC已启用，提供额外的安全保护"
			}
		case "EnableFirewall":
			if value == 0 {
				setting.Risk = "高"
				setting.Description += "。防火墙已禁用，系统暴露于网络攻击风险"
			} else {
				setting.Risk = "低"
				setting.Description += "。防火墙已启用，提供网络保护"
			}
		case "AUOptions":
			switch value {
			case 1:
				setting.Risk = "高"
				setting.Description += "。自动更新已禁用"
			case 2:
				setting.Risk = "中"
				setting.Description += "。更新前通知"
			case 3:
				setting.Risk = "低"
				setting.Description += "。自动下载并通知安装"
			case 4:
				setting.Risk = "低"
				setting.Description += "。自动下载并安装更新"
			}
		}

		settings = append(settings, setting)
	}

	return settings, nil
}

func (w *windowsRegistryAnalyzer) GetAllRegistryKeys() ([]RegistryKey, error) {
	var keys []RegistryKey

	// 定义要扫描的重要注册表路径
	paths := []string{
		`SOFTWARE`,
		`SYSTEM`,
		`SECURITY`,
	}

	// 打开 HKEY_LOCAL_MACHINE
	for _, path := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue // 跳过无法访问的键
		}
		defer k.Close()

		// 获取所有子键
		subkeys, err := k.ReadSubKeyNames(-1)
		if err != nil {
			continue
		}

		// 遍历子键
		for _, subkey := range subkeys {
			fullPath := path + "\\" + subkey
			sk, err := registry.OpenKey(registry.LOCAL_MACHINE, fullPath, registry.READ)
			if err != nil {
				continue
			}
			defer sk.Close()

			// 获取值
			valueNames, err := sk.ReadValueNames(-1)
			if err != nil {
				continue
			}

			for _, name := range valueNames {
				val, valType, err := sk.GetValue(name, nil)
				if err != nil {
					continue
				}

				// 获取最后修改时间
				info, err := sk.Stat()
				if err != nil {
					continue
				}

				// 将值类型转换为字符串
				var typeStr string
				switch valType {
				case registry.SZ:
					typeStr = "REG_SZ"
				case registry.EXPAND_SZ:
					typeStr = "REG_EXPAND_SZ"
				case registry.BINARY:
					typeStr = "REG_BINARY"
				case registry.DWORD:
					typeStr = "REG_DWORD"
				case registry.QWORD:
					typeStr = "REG_QWORD"
				case registry.MULTI_SZ:
					typeStr = "REG_MULTI_SZ"
				default:
					typeStr = fmt.Sprintf("REG_TYPE_%d", valType)
				}

				key := RegistryKey{
					Path:     fullPath,
					Name:     name,
					Type:     typeStr,
					Value:    fmt.Sprintf("%v", val),
					Modified: info.ModTime(),
				}
				keys = append(keys, key)
			}
		}
	}

	return keys, nil
}

func init() {
    registerRegistryAnalyzer("windows", func() (RegistryAnalyzer, error) {
        return &windowsRegistryAnalyzer{}, nil
    })
}

// 内部辅助函数

func getRegistryValueTypeName(valueType uint32) string {
	switch valueType {
	case registry.NONE:
		return "NONE"
	case registry.SZ:
		return "SZ"
	case registry.EXPAND_SZ:
		return "EXPAND_SZ"
	case registry.BINARY:
		return "BINARY"
	case registry.DWORD:
		return "DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "LINK"
	case registry.MULTI_SZ:
		return "MULTI_SZ"
	case registry.RESOURCE_LIST:
		return "RESOURCE_LIST"
	case registry.QWORD:
		return "QWORD"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", valueType)
	}
}

func isSuspiciousRegistryValue(value string) bool {
	value = strings.ToLower(value)

	// 检查可疑文件扩展名
	suspiciousExts := []string{
		".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1",
		".js", ".wsf", ".hta", ".scr", ".pif",
	}

	for _, ext := range suspiciousExts {
		if strings.HasSuffix(value, ext) {
			// 检查文件是否存在
			if _, err := os.Stat(value); err != nil {
				return true // 可疑：引用了不存在的可执行文件
			}

			// 检查是否在系统目录之外
			sysDir := os.Getenv("SystemRoot")
			progFiles := os.Getenv("ProgramFiles")
			progFilesX86 := os.Getenv("ProgramFiles(x86)")

			if !strings.HasPrefix(value, sysDir) &&
				!strings.HasPrefix(value, progFiles) &&
				!strings.HasPrefix(value, progFilesX86) {
				return true // 可疑：可执行文件不在标准系统目录
			}
		}
	}

	// 检查可疑命令或参数
	suspiciousCommands := []string{
		"cmd.exe", "powershell", "wscript.exe", "cscript.exe",
		"rundll32.exe", "regsvr32.exe", "mshta.exe",
		"-enc", "-encodedcommand", "-nop", "-windowstyle hidden",
		"downloadstring", "iex", "invoke-expression",
	}

	for _, cmd := range suspiciousCommands {
		if strings.Contains(value, cmd) {
			return true
		}
	}

	// 检查可疑URL或IP地址
	if strings.Contains(value, "http://") || strings.Contains(value, "https://") {
		return true // 可疑：包含URL
	}

	// 检查Base64编码特征
	if len(value) > 100 && isBase64Like(value) {
		return true // 可疑：可能包含Base64编码的payload
	}

	return false
}

func isBase64Like(s string) bool {
	// 简单检查是否像Base64编码的字符串
	base64Chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	nonBase64Count := 0

	for _, c := range s {
		if !strings.ContainsRune(base64Chars, c) {
			nonBase64Count++
		}
	}

	// 如果非Base64字符的比例很低，可能是Base64编码
	return float64(nonBase64Count)/float64(len(s)) < 0.1
}
