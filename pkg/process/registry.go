package process

import (
    "sync"
)

// processAnalyzerInitializer is a function that creates a new ProcessAnalyzer
type processAnalyzerInitializer func() (ProcessAnalyzer, error)

var (
    analyzerRegistry = make(map[string]processAnalyzerInitializer)
    registryMutex    sync.RWMutex
)

// registerProcessAnalyzer registers a process analyzer initializer for a specific OS
func registerProcessAnalyzer(os string, initializer processAnalyzerInitializer) {
    registryMutex.Lock()
    defer registryMutex.Unlock()
    analyzerRegistry[os] = initializer
}

// getProcessAnalyzer returns a process analyzer initializer for a specific OS
func getProcessAnalyzer(os string) (processAnalyzerInitializer, bool) {
    registryMutex.RLock()
    defer registryMutex.RUnlock()
    initializer, ok := analyzerRegistry[os]
    return initializer, ok
}
