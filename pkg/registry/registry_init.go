package registry

import (
    "sync"
)

// registryAnalyzerInitializer is a function that creates a new RegistryAnalyzer
type registryAnalyzerInitializer func() (RegistryAnalyzer, error)

var (
    analyzerRegistry = make(map[string]registryAnalyzerInitializer)
    registryMutex    sync.RWMutex
)

// registerRegistryAnalyzer registers a registry analyzer initializer for a specific OS
func registerRegistryAnalyzer(os string, initializer registryAnalyzerInitializer) {
    registryMutex.Lock()
    defer registryMutex.Unlock()
    analyzerRegistry[os] = initializer
}

// getRegistryAnalyzer returns a registry analyzer initializer for a specific OS
func getRegistryAnalyzer(os string) (registryAnalyzerInitializer, bool) {
    registryMutex.RLock()
    defer registryMutex.RUnlock()
    initializer, ok := analyzerRegistry[os]
    return initializer, ok
}
