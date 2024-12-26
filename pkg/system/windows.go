package system

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsSystemAnalyzer struct{}

func newSystemAnalyzer() (SystemAnalyzer, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return &windowsSystemAnalyzer{}, nil
}

type OSVERSIONINFOEXW struct {
	OSVersionInfoSize uint32
	MajorVersion     uint32
	MinorVersion     uint32
	BuildNumber      uint32
	PlatformId       uint32
	CSDVersion       [128]uint16
	ServicePackMajor uint16
	ServicePackMinor uint16
	SuiteMask        uint16
	ProductType      byte
	Reserved         byte
}

func (w *windowsSystemAnalyzer) GetSystemInfo() (*SystemInfo, error) {
	var si SystemInfo
	var err error

	// 获取主机名
	si.Hostname, err = os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("获取主机名失败: %v", err)
	}

	// 获取操作系统信息
	si.OS = runtime.GOOS
	si.Architecture = runtime.GOARCH

	// 获取系统版本
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	rtlGetVersion := ntdll.NewProc("RtlGetVersion")

	var vi OSVERSIONINFOEXW
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	
	ret, _, _ := rtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if ret == 0 {
		si.Version = fmt.Sprintf("%d.%d.%d", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)
	}

	// 获取域信息
	var size uint32 = 256
	domain := make([]uint16, size)
	err = windows.GetComputerNameEx(windows.ComputerNameDnsDomain, &domain[0], &size)
	if err == nil {
		si.Domain = windows.UTF16ToString(domain[:size])
	}

	// 获取启动时间
	if handle, err := windows.GetCurrentProcess(); err == nil {
		var creationTime, exitTime, kernelTime, userTime windows.Filetime
		if err := windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
			si.BootTime = time.Unix(0, creationTime.Nanoseconds())
			si.Uptime = time.Since(si.BootTime)
		}
	}

	// 获取CPU信息
	si.CPUInfo = getCPUInfo()

	// 获取内存信息
	si.MemoryInfo = getMemoryInfo()

	// 获取磁盘信息
	si.DiskInfo = getDiskInfo()

	return &si, nil
}

const (
	FILTER_NORMAL_ACCOUNT = 0x0002
	LG_INCLUDE_INDIRECT  = 0x0001
)

func (w *windowsSystemAnalyzer) GetUsers() ([]UserInfo, error) {
	var users []UserInfo

	// 获取所有用户
	var level uint32 = 3 // USER_INFO_3 level
	var entriesRead, totalEntries, resumeHandle uint32
	var bufPtr *byte

	err := windows.NetUserEnum(nil, level, FILTER_NORMAL_ACCOUNT,
		&bufPtr, 0xFFFFFFFF, &entriesRead, &totalEntries, &resumeHandle)
	if err != nil {
		return nil, fmt.Errorf("获取用户列表失败: %v", err)
	}
	defer windows.NetApiBufferFree(bufPtr)

	type USER_INFO_3 struct {
		Name            *uint16
		Password        *uint16
		PasswordAge     uint32
		Priv            uint32
		HomeDir         *uint16
		Comment         *uint16
		Flags           uint32
		ScriptPath      *uint16
		AuthFlags       uint32
		FullName        *uint16
		UsrComment      *uint16
		Params          *uint16
		Workstations    *uint16
		LastLogon       uint32
		LastLogoff      uint32
		AcctExpires     uint32
		MaxStorage      uint32
		UnitsPerWeek    uint32
		LogonHours      *byte
		BadPwCount      uint32
		NumLogons       uint32
		LogonServer     *uint16
		CountryCode     uint32
		CodePage        uint32
		UserID          uint32
		PrimaryGroupID  uint32
		Profile         *uint16
		HomeDirDrive    *uint16
		PasswordExpired uint32
	}

	var userInfo *USER_INFO_3
	userInfo = (*USER_INFO_3)(unsafe.Pointer(bufPtr))

	for i := uint32(0); i < entriesRead; i++ {
		user := UserInfo{
			Username:   windows.UTF16PtrToString(userInfo.Name),
			FullName:   windows.UTF16PtrToString(userInfo.FullName),
			HomeDir:    windows.UTF16PtrToString(userInfo.HomeDir),
			LastLogin:  time.Unix(int64(userInfo.LastLogon), 0),
			IsDisabled: userInfo.Flags&0x0002 != 0, // UF_ACCOUNTDISABLE
			IsLocked:   userInfo.Flags&0x0010 != 0, // UF_LOCKOUT
		}

		// 获取用户组
		var groupBuf *byte
		var groupEntriesRead, totalGroupEntries uint32

		// 使用 Netapi32.dll 获取用户组信息
		netapi32 := windows.NewLazySystemDLL("netapi32.dll")
		netUserGetLocalGroups := netapi32.NewProc("NetUserGetLocalGroups")

		ret, _, _ := netUserGetLocalGroups.Call(
			0, // servername (NULL)
			uintptr(unsafe.Pointer(userInfo.Name)),
			0, // level
			uintptr(LG_INCLUDE_INDIRECT),
			uintptr(unsafe.Pointer(&groupBuf)),
			0xFFFFFFFF,
			uintptr(unsafe.Pointer(&groupEntriesRead)),
			uintptr(unsafe.Pointer(&totalGroupEntries)),
		)

		if ret == 0 {
			defer windows.NetApiBufferFree(groupBuf)

			type LOCALGROUP_USERS_INFO_0 struct {
				Name *uint16
			}

			var groupInfo *LOCALGROUP_USERS_INFO_0
			groupInfo = (*LOCALGROUP_USERS_INFO_0)(unsafe.Pointer(groupBuf))

			for j := uint32(0); j < groupEntriesRead; j++ {
				groupName := windows.UTF16PtrToString(groupInfo.Name)
				user.Groups = append(user.Groups, groupName)
				if strings.EqualFold(groupName, "Administrators") {
					user.IsAdmin = true
				}
				groupInfo = (*LOCALGROUP_USERS_INFO_0)(unsafe.Pointer(uintptr(unsafe.Pointer(groupInfo)) + unsafe.Sizeof(*groupInfo)))
			}
		}

		users = append(users, user)
		userInfo = (*USER_INFO_3)(unsafe.Pointer(uintptr(unsafe.Pointer(userInfo)) + unsafe.Sizeof(*userInfo)))
	}

	return users, nil
}

func (w *windowsSystemAnalyzer) DetectSuspiciousUsers() ([]UserInfo, error) {
	var suspicious []UserInfo

	users, err := w.GetUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		// 检查可疑特征
		if isSuspiciousUser(user) {
			suspicious = append(suspicious, user)
		}
	}

	return suspicious, nil
}

func getCPUInfo() []CPUInfo {
	// 使用 windows API 获取 CPU 信息
	var cpuInfo []CPUInfo
	
	// 获取 CPU 使用率
	h, err := windows.GetCurrentProcess()
	if err == nil {
		var creationTime, exitTime, kernelTime, userTime windows.Filetime
		if err := windows.GetProcessTimes(h, &creationTime, &exitTime, &kernelTime, &userTime); err == nil {
			// 计算 CPU 使用率
			kernelNs := kernelTime.Nanoseconds()
			userNs := userTime.Nanoseconds()
			totalNs := kernelNs + userNs
			
			// 获取系统启动时间
			var uptime uint64
			kernel32 := windows.NewLazySystemDLL("kernel32.dll")
			getTickCount64 := kernel32.NewProc("GetTickCount64")
			r1, _, _ := getTickCount64.Call()
			uptime = uint64(r1)
			
			if uptime > 0 {
				usage := float64(totalNs) / float64(uptime*10000000) * 100
				cpuInfo = append(cpuInfo, CPUInfo{
					Model:       "Unknown",  // TODO: 获取具体CPU型号
					Cores:       runtime.NumCPU(),
					Threads:     runtime.NumCPU(),
					ClockSpeed:  0,  // TODO: 获取具体时钟速度
					Temperature: 0,  // TODO: 获取具体温度
					Usage:       usage,
				})
			}
		}
	}
	
	// 如果获取失败，返回默认值
	if len(cpuInfo) == 0 {
		cpuInfo = append(cpuInfo, CPUInfo{
			Model:       "Unknown",
			Cores:       runtime.NumCPU(),
			Threads:     runtime.NumCPU(),
			ClockSpeed:  0,
			Temperature: 0,
			Usage:       0,
		})
	}
	
	return cpuInfo
}

type MEMORYSTATUSEX struct {
	dwLength                uint32
	dwMemoryLoad           uint32
	ullTotalPhys           uint64
	ullAvailPhys           uint64
	ullTotalPageFile       uint64
	ullAvailPageFile       uint64
	ullTotalVirtual        uint64
	ullAvailVirtual        uint64
	ullAvailExtendedVirtual uint64
}

func getMemoryInfo() MemoryInfo {
	var memInfo MemoryInfo
	var statex MEMORYSTATUSEX
	statex.dwLength = uint32(unsafe.Sizeof(statex))

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&statex)))
	if ret != 0 {
		memInfo.Total = statex.ullTotalPhys
		memInfo.Available = statex.ullAvailPhys
		memInfo.Used = memInfo.Total - memInfo.Available
		memInfo.SwapTotal = statex.ullTotalPageFile
		memInfo.SwapUsed = statex.ullTotalPageFile - statex.ullAvailPageFile
	}
	return memInfo
}

func getDiskInfo() []DiskInfo {
	var diskInfo []DiskInfo
	// 获取所有驱动器
	drives, err := windows.GetLogicalDrives()
	if err != nil {
		return diskInfo
	}

	for i := 0; i < 26; i++ {
		if drives&(1<<uint(i)) != 0 {
			drive := string('A'+i) + ":\\"
			var freeBytesAvailable, totalBytes, totalFreeBytes uint64
			if err := windows.GetDiskFreeSpaceEx(
				windows.StringToUTF16Ptr(drive),
				&freeBytesAvailable,
				&totalBytes,
				&totalFreeBytes,
			); err == nil {
				info := DiskInfo{
					Device:     drive,
					MountPoint: drive,
					FileSystem: getFileSystem(drive),
					Total:      totalBytes,
					Available:  freeBytesAvailable,
					Used:       totalBytes - freeBytesAvailable,
				}
				diskInfo = append(diskInfo, info)
			}
		}
	}
	return diskInfo
}

func getFileSystem(drive string) string {
	var volumeName, fsName [256]uint16
	var serialNumber uint32
	var maxComponentLength, fsFlags uint32
	err := windows.GetVolumeInformation(
		windows.StringToUTF16Ptr(drive),
		&volumeName[0],
		uint32(len(volumeName)),
		&serialNumber,
		&maxComponentLength,
		&fsFlags,
		&fsName[0],
		uint32(len(fsName)),
	)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(fsName[:])
}

func isSuspiciousUser(user UserInfo) bool {
	// 检查可疑特征：
	// 1. 最近创建的管理员账户
	// 2. 从未登录的账户
	// 3. 长期未使用但未禁用的账户
	// 4. 具有异常权限的账户
	if user.IsAdmin && time.Since(user.LastPasswdChange) < 24*time.Hour {
		return true
	}
	if user.LastLogin.IsZero() && !user.IsDisabled {
		return true
	}
	if time.Since(user.LastLogin) > 180*24*time.Hour && !user.IsDisabled {
		return true
	}
	return false
}
