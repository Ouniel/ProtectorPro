//go:build windows
package eventlog

import (
	"fmt"
	"log"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API 常量
const (
	EVENTLOG_SEQUENTIAL_READ = 0x0001
	EVENTLOG_BACKWARDS_READ  = 0x0008
	EVENTLOG_SEEK_READ      = 0x0002
	EVENTLOG_FORWARDS_READ  = 0x0004

	EVENTLOG_SUCCESS          = 0x0000
	EVENTLOG_ERROR_TYPE      = 0x0001
	EVENTLOG_WARNING_TYPE    = 0x0002
	EVENTLOG_INFORMATION_TYPE = 0x0004
	EVENTLOG_AUDIT_SUCCESS   = 0x0008
	EVENTLOG_AUDIT_FAILURE   = 0x0010
)

// EVENTLOGRECORD Windows API 结构体
type EVENTLOGRECORD struct {
	Length              uint32
	Reserved            uint32
	RecordNumber        uint32
	TimeGenerated      uint32
	TimeWritten        uint32
	EventID            uint32
	EventType          uint16
	NumStrings         uint16
	EventCategory      uint16
	ReservedFlags      uint16
	ClosingRecordNumber uint32
	StringOffset       uint32
	UserSidLength      uint32
	UserSidOffset      uint32
	DataLength         uint32
	DataOffset         uint32
}

var (
	modadvapi32 = windows.NewLazyDLL("advapi32.dll")
	
	procOpenEventLogW = modadvapi32.NewProc("OpenEventLogW")
	procReadEventLogW = modadvapi32.NewProc("ReadEventLogW")
	procCloseEventLog = modadvapi32.NewProc("CloseEventLog")
)

// windowsEventLogAnalyzer Windows事件日志分析器
type windowsEventLogAnalyzer struct {
	handle windows.Handle
}

// isAdmin 检查当前进程是否具有管理员权限
func isAdmin() bool {
	var sid *windows.SID

	// 初始化内置管理员组的 SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// 检查当前进程令牌是否属于管理员组
	token := windows.Token(0)
	member, err := token.IsMember(sid)
	return err == nil && member
}

// newWindowsEventLogAnalyzer 创建Windows事件日志分析器
func newWindowsEventLogAnalyzer() (EventLogAnalyzer, error) {
	if !isAdmin() {
		return nil, fmt.Errorf("需要管理员权限才能访问安全事件日志")
	}

	source := syscall.StringToUTF16Ptr("Security")
	server := (*uint16)(nil) // 本地计算机

	ret, _, err := procOpenEventLogW.Call(
		uintptr(unsafe.Pointer(server)),
		uintptr(unsafe.Pointer(source)),
	)

	if ret == 0 {
		if err == syscall.ERROR_ACCESS_DENIED {
			return nil, fmt.Errorf("访问被拒绝：需要管理员权限才能访问安全事件日志")
		}
		return nil, fmt.Errorf("打开安全事件日志失败: %v", err)
	}

	handle := windows.Handle(ret)

	return &windowsEventLogAnalyzer{
		handle: handle,
	}, nil
}

// Close 关闭事件日志句柄
func (w *windowsEventLogAnalyzer) Close() error {
	if w.handle != 0 {
		ret, _, _ := procCloseEventLog.Call(uintptr(w.handle))
		if ret == 0 {
			return fmt.Errorf("关闭事件日志句柄失败")
		}
		w.handle = 0
	}
	return nil
}

// readEventLog 读取事件日志
func (w *windowsEventLogAnalyzer) readEventLog(flags uint32, offset uint32, bufferSize uint32) ([]byte, error) {
	var bytesRead, minBytesNeeded uint32
	buffer := make([]byte, bufferSize)

	ret, _, err := procReadEventLogW.Call(
		uintptr(w.handle),
		uintptr(flags),
		uintptr(offset),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(bufferSize),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(unsafe.Pointer(&minBytesNeeded)),
	)

	if ret == 0 {
		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			// 如果缓冲区不足，使用建议的大小重新尝试
			newBuffer := make([]byte, minBytesNeeded)
			ret, _, err = procReadEventLogW.Call(
				uintptr(w.handle),
				uintptr(flags),
				uintptr(offset),
				uintptr(unsafe.Pointer(&newBuffer[0])),
				uintptr(minBytesNeeded),
				uintptr(unsafe.Pointer(&bytesRead)),
				uintptr(unsafe.Pointer(&minBytesNeeded)),
			)
			
			if ret == 0 {
				if err == syscall.ERROR_HANDLE_EOF {
					return nil, fmt.Errorf("EOF")
				}
				return nil, fmt.Errorf("读取事件日志失败: %v", err)
			}
			
			buffer = newBuffer
		} else if err == syscall.ERROR_HANDLE_EOF {
			return nil, fmt.Errorf("EOF")
		} else {
			return nil, fmt.Errorf("读取事件日志失败: %v", err)
		}
	}

	if bytesRead == 0 {
		return nil, nil
	}

	log.Printf("成功读取 %d 字节的事件日志", bytesRead)
	return buffer[:bytesRead], nil
}

// getEventMessage 获取事件消息
func getEventMessage(buffer []byte, record *EVENTLOGRECORD) string {
	if record.NumStrings == 0 || record.StringOffset >= uint32(len(buffer)) {
		return ""
	}
	
	var messages []string
	stringOffset := record.StringOffset
	
	for i := uint16(0); i < record.NumStrings; i++ {
		if stringOffset >= uint32(len(buffer)) {
			break
		}
		
		str := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buffer[stringOffset])))
		if str != "" {
			messages = append(messages, str)
		}
		
		// 移动到下一个字符串
		stringLen := uint32(len(str) * 2) // UTF-16 字符占用 2 字节
		if stringLen == 0 {
			break
		}
		stringOffset += stringLen + 2 // 加2是为了跳过结尾的null字符
	}
	
	return strings.Join(messages, " ")
}

// getEventLevel 获取事件级别
func getEventLevel(eventType uint16) EventLevel {
	switch eventType {
	case EVENTLOG_ERROR_TYPE:
		return EventLevelError
	case EVENTLOG_WARNING_TYPE:
		return EventLevelWarning
	case EVENTLOG_INFORMATION_TYPE:
		return EventLevelInformation
	case EVENTLOG_AUDIT_SUCCESS:
		return EventLevelSuccess
	default:
		return EventLevelInformation
	}
}

// GetLoginEvents 获取登录事件
func (w *windowsEventLogAnalyzer) GetLoginEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	flags := uint32(EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ)  // 改为正向读取
	var offset uint32 = 0
	bufferSize := uint32(32768) // 增加缓冲区大小
	
	for {
		buffer, err := w.readEventLog(flags, offset, bufferSize)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Printf("读取事件日志出错: %v", err)
			return nil, fmt.Errorf("读取登录事件失败: %v", err)
		}
		
		if len(buffer) == 0 {
			break
		}
		
		recordOffset := uint32(0)
		for recordOffset < uint32(len(buffer)) {
			record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[recordOffset]))
			if record.Length == 0 || recordOffset+record.Length > uint32(len(buffer)) {
				break
			}
			
			// 提取真实的事件ID（去掉高位）
			eventID := record.EventID & 0x0000FFFF
			
			// 检查事件时间
			eventTime := time.Unix(int64(record.TimeGenerated), 0)
			log.Printf("发现事件: ID=%d (原始ID=%d), 类型=%d, 时间=%v", 
				eventID, record.EventID, record.EventType, eventTime)
			
			if eventTime.Before(since) {
				log.Printf("事件时间 %v 早于筛选时间 %v，跳过", eventTime, since)
				recordOffset += record.Length
				continue
			}
			
			// 判断是否为登录事件 (事件ID: 4624 成功登录, 4625 登录失败)
			if eventID == 4624 || eventID == 4625 {
				message := getEventMessage(buffer[recordOffset:recordOffset+record.Length], record)
				log.Printf("找到登录事件: ID=%d, 类型=%d, 消息=%s", eventID, record.EventType, message)
				
				event := SecurityEvent{
					EventID:     eventID,
					EventType:   EventTypeLogin,
					Time:        eventTime,
					Level:      getEventLevel(record.EventType),
					Source:     "Security",
					Description: message,
				}
				events = append(events, event)
			} else {
				log.Printf("不是登录事件，跳过: ID=%d", eventID)
			}
			
			// 移动到下一个记录
			recordOffset += record.Length
		}
		
		offset += uint32(len(buffer))
		
		// 如果没有更多数据可读，退出循环
		if len(buffer) < int(bufferSize) {
			break
		}
	}
	
	log.Printf("总共找到 %d 条登录事件", len(events))
	return events, nil
}

// GetPrivilegeEvents 获取权限事件
func (w *windowsEventLogAnalyzer) GetPrivilegeEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取权限事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为权限事件 (事件ID: 4672 特权分配, 4673 特权服务调用)
		if record.EventID == 4672 || record.EventID == 4673 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypePrivilege,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetProcessEvents 获取进程事件
func (w *windowsEventLogAnalyzer) GetProcessEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取进程事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为进程事件 (事件ID: 4688 进程创建, 4689 进程终止)
		if record.EventID == 4688 || record.EventID == 4689 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeProcess,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetAuditEvents 获取审计事件
func (w *windowsEventLogAnalyzer) GetAuditEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取审计事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为审计事件 (事件ID: 4719 审计策略更改)
		if record.EventID == 4719 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeAudit,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetUserAccountEvents 获取用户账户事件
func (w *windowsEventLogAnalyzer) GetUserAccountEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取用户账户事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为用户账户事件 (事件ID: 4720 创建, 4726 删除, 4738 修改)
		if record.EventID == 4720 || record.EventID == 4726 || record.EventID == 4738 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeUserAccount,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetGroupPolicyEvents 获取组策略事件
func (w *windowsEventLogAnalyzer) GetGroupPolicyEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取组策略事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为组策略事件 (事件ID: 4739 域策略修改, 5447 组策略筛选)
		if record.EventID == 4739 || record.EventID == 5447 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeGroupPolicy,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetServiceEvents 获取服务事件
func (w *windowsEventLogAnalyzer) GetServiceEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取服务事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为服务事件 (事件ID: 7034 服务异常终止, 7036 服务状态更改)
		if record.EventID == 7034 || record.EventID == 7036 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeService,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "System",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetFirewallEvents 获取防火墙事件
func (w *windowsEventLogAnalyzer) GetFirewallEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	buffer, err := w.readEventLog(
		EVENTLOG_SEQUENTIAL_READ|EVENTLOG_BACKWARDS_READ,
		0,
		8192, // 初始缓冲区大小
	)
	
	if err != nil {
		return nil, fmt.Errorf("读取防火墙事件失败: %v", err)
	}
	
	offset := uint32(0)
	for offset < uint32(len(buffer)) {
		record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[offset]))
		
		// 检查事件时间
		eventTime := time.Unix(int64(record.TimeGenerated), 0)
		if eventTime.Before(since) {
			break
		}
		
		// 判断是否为防火墙事件 (事件ID: 5025 服务停止, 5031 应用程序被阻止)
		if record.EventID == 5025 || record.EventID == 5031 {
			event := SecurityEvent{
				EventID:     record.EventID,
				EventType:   EventTypeFirewall,
				Time:        eventTime,
				Level:      getEventLevel(record.EventType),
				Source:     "Security",
				Description: getEventMessage(buffer[offset:offset+record.Length], record),
			}
			events = append(events, event)
		}
		
		offset += record.Length
	}
	
	return events, nil
}

// GetAllEvents 获取所有事件
func (w *windowsEventLogAnalyzer) GetAllEvents(since time.Time) ([]SecurityEvent, error) {
	var events []SecurityEvent
	
	// 读取最近的事件
	flags := uint32(EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ)
	var offset uint32 = 0
	bufferSize := uint32(32768) // 32KB 缓冲区
	
	for {
		buffer, err := w.readEventLog(flags, offset, bufferSize)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Printf("读取事件日志出错: %v", err)
			return nil, fmt.Errorf("读取事件失败: %v", err)
		}
		
		if len(buffer) == 0 {
			break
		}
		
		recordOffset := uint32(0)
		for recordOffset < uint32(len(buffer)) {
			record := (*EVENTLOGRECORD)(unsafe.Pointer(&buffer[recordOffset]))
			if record.Length == 0 || recordOffset+record.Length > uint32(len(buffer)) {
				break
			}
			
			// 提取真实的事件ID（去掉高位）
			eventID := record.EventID & 0x0000FFFF
			
			// 检查事件时间
			eventTime := time.Unix(int64(record.TimeGenerated), 0)
			
			// 获取事件消息
			message := getEventMessage(buffer[recordOffset:recordOffset+record.Length], record)
			
			// 获取用户信息
			var user string
			if record.UserSidLength > 0 && record.UserSidOffset < record.Length {
				sidData := buffer[recordOffset+record.UserSidOffset : recordOffset+record.UserSidOffset+record.UserSidLength]
				user = getUserFromSID(sidData)
			}
			
			// 获取计算机名
			computer := getSourceName(buffer[recordOffset:recordOffset+record.Length], record)
			
			// 创建事件记录
			event := SecurityEvent{
				EventID:      eventID,
				EventType:    getEventType(eventID),
				Time:         eventTime,
				Level:       getEventLevel(record.EventType),
				Source:      "Security",
				Description: message,
				Computer:    computer,
				User:        user,
			}
			
			// 只添加指定时间之后的事件
			if !eventTime.Before(since) {
				events = append(events, event)
			}
			
			// 移动到下一个记录
			recordOffset += record.Length
		}
		
		// 如果没有更多数据可读，退出循环
		if len(buffer) == 0 || recordOffset == 0 {
			break
		}
		
		// 更新偏移量
		offset = recordOffset
	}
	
	log.Printf("总共读取到 %d 条事件", len(events))
	return events, nil
}

// getSourceName 获取事件源名称（计算机名）
func getSourceName(buffer []byte, record *EVENTLOGRECORD) string {
	if len(buffer) < int(unsafe.Sizeof(*record)) {
		return ""
	}
	sourceOffset := uint32(unsafe.Sizeof(*record))
	if sourceOffset >= uint32(len(buffer)) {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(&buffer[sourceOffset])))
}

// getUserFromSID 从SID数据获取用户名
func getUserFromSID(sidData []byte) string {
	sid := (*windows.SID)(unsafe.Pointer(&sidData[0]))
	
	// 获取账户名和域名
	var nameUse uint32
	nameLen := uint32(0)
	domainLen := uint32(0)
	
	// 首次调用获取所需的缓冲区大小
	windows.LookupAccountSid(nil, sid, nil, &nameLen, nil, &domainLen, &nameUse)
	
	if nameLen == 0 {
		return ""
	}
	
	name := make([]uint16, nameLen)
	domain := make([]uint16, domainLen)
	
	// 第二次调用获取实际的用户名和域名
	err := windows.LookupAccountSid(nil, sid, &name[0], &nameLen, &domain[0], &domainLen, &nameUse)
	if err != nil {
		return ""
	}
	
	userName := windows.UTF16ToString(name)
	domainName := windows.UTF16ToString(domain)
	
	if domainName != "" {
		return domainName + "\\" + userName
	}
	return userName
}

// getEventType 根据事件ID确定事件类型
func getEventType(eventID uint32) EventType {
	switch eventID {
	case 4624: // 成功登录
		return EventTypeLogin
	case 4625: // 登录失败
		return EventTypeLogin
	case 4634: // 注销
		return EventTypeLogin
	case 4647: // 用户启动的注销
		return EventTypeLogin
	case 4648: // 使用显式凭据尝试登录
		return EventTypeLogin
	case 4649: // 重放攻击检测
		return EventTypeLogin
	case 4675: // SIDs 被过滤
		return EventTypeLogin
	case 4778: // 重新连接到 Windows 会话
		return EventTypeLogin
	case 4779: // 断开 Windows 会话连接
		return EventTypeLogin

	case 4672: // 使用特殊权限登录
		return EventTypePrivilege
	case 4673: // 特权服务被调用
		return EventTypePrivilege
	case 4674: // 尝试对特权对象执行操作
		return EventTypePrivilege
	case 4985: // 状态更改的事务管理器
		return EventTypePrivilege
	
	case 4688: // 新进程已创建
		return EventTypeProcess
	case 4689: // 进程已退出
		return EventTypeProcess
	case 4690: // 尝试复制句柄到进程
		return EventTypeProcess
	case 4691: // 间接访问对象已添加到进程
		return EventTypeProcess
	case 4696: // 主令牌被分配给进程
		return EventTypeProcess
	case 4697: // 尝试安装服务
		return EventTypeProcess

	case 4715: // 审核策略已更改
		return EventTypeAudit
	case 4719: // 系统审核策略已更改
		return EventTypeAudit
	case 4817: // 对象审核策略已更改
		return EventTypeAudit
	case 4902: // 每用户审核策略表已创建
		return EventTypeAudit
	case 4904: // 尝试注册安全事件源
		return EventTypeAudit
	case 4905: // 尝试注销安全事件源
		return EventTypeAudit
	case 4906: // CrashOnAuditFail 值已更改
		return EventTypeAudit
	case 4907: // 审核设置已更改
		return EventTypeAudit
	case 4908: // 特殊组已分配给新登录
		return EventTypeAudit
	
	case 4720: // 用户账户已创建
		return EventTypeUserAccount
	case 4722: // 用户账户已启用
		return EventTypeUserAccount
	case 4723: // 尝试更改账户密码
		return EventTypeUserAccount
	case 4724: // 尝试重置账户密码
		return EventTypeUserAccount
	case 4725: // 用户账户已禁用
		return EventTypeUserAccount
	case 4726: // 用户账户已删除
		return EventTypeUserAccount
	case 4738: // 用户账户已更改
		return EventTypeUserAccount
	case 4740: // 用户账户已被锁定
		return EventTypeUserAccount
	case 4767: // 用户账户已解锁
		return EventTypeUserAccount
	case 4781: // 用户账户名已更改
		return EventTypeUserAccount

	case 4739: // 域策略已更改
		return EventTypeGroupPolicy
	case 5447: // 过滤平台筛选器已更改
		return EventTypeGroupPolicy
	case 5448: // 显示筛选器已更改
		return EventTypeGroupPolicy
	case 5449: // 提供程序筛选器已更改
		return EventTypeGroupPolicy
	case 5450: // IPSEC 策略代理已启动
		return EventTypeGroupPolicy

	case 7034: // 服务意外终止
		return EventTypeService
	case 7035: // 服务发送控制
		return EventTypeService
	case 7036: // 服务状态已更改
		return EventTypeService
	case 7040: // 服务启动类型已更改
		return EventTypeService
	case 7045: // 新服务已安装
		return EventTypeService

	case 5025: // 防火墙服务已停止
		return EventTypeFirewall
	case 5031: // 应用程序或服务已阻止
		return EventTypeFirewall
	case 5152: // 防火墙已阻止数据包
		return EventTypeFirewall
	case 5153: // 防火墙已允许连接
		return EventTypeFirewall
	case 5155: // 防火墙已阻止应用程序
		return EventTypeFirewall
	case 5157: // 防火墙已阻止连接
		return EventTypeFirewall
	case 5159: // 防火墙已允许应用程序
		return EventTypeFirewall

	default:
		return EventTypeOther
	}
}

func init() {
	// 在 init 函数中注册 Windows 的初始化函数
	registerEventLogAnalyzer("windows", newWindowsEventLogAnalyzer)
}
