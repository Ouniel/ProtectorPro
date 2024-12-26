package network

import (
    "sync"
)

// networkAnalyzerInitializer is a function that creates a new NetworkAnalyzer
type networkAnalyzerInitializer func() (NetworkAnalyzer, error)

var (
    analyzerRegistry = make(map[string]networkAnalyzerInitializer)
    registryMutex    sync.RWMutex
)

// registerNetworkAnalyzer registers a network analyzer initializer for a specific OS
func registerNetworkAnalyzer(os string, initializer networkAnalyzerInitializer) {
    registryMutex.Lock()
    defer registryMutex.Unlock()
    analyzerRegistry[os] = initializer
}

// getNetworkAnalyzer returns a network analyzer initializer for a specific OS
func getNetworkAnalyzer(os string) (networkAnalyzerInitializer, bool) {
    registryMutex.RLock()
    defer registryMutex.RUnlock()
    initializer, ok := analyzerRegistry[os]
    return initializer, ok
}
