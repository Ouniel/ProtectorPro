package eventlog

import (
	"sync"
)

// analyzerInitializer 创建新的事件日志分析器的函数
type analyzerInitializer func() (EventLogAnalyzer, error)

var (
	analyzerFactories = make(map[string]analyzerInitializer)
	factoryMutex      sync.RWMutex
)

// registerEventLogAnalyzer 注册特定操作系统的事件日志分析器初始化函数
func registerEventLogAnalyzer(os string, initializer analyzerInitializer) {
	factoryMutex.Lock()
	defer factoryMutex.Unlock()
	analyzerFactories[os] = initializer
}

// getEventLogAnalyzer 获取特定操作系统的事件日志分析器初始化函数
func getEventLogAnalyzer(os string) (analyzerInitializer, bool) {
	factoryMutex.RLock()
	defer factoryMutex.RUnlock()
	initializer, ok := analyzerFactories[os]
	return initializer, ok
}
