package eventlog

import (
	"fmt"
	"runtime"
)

// NewEventLogAnalyzer creates a new event log analyzer based on the current operating system
func NewEventLogAnalyzer() (EventLogAnalyzer, error) {
	initializer, ok := getEventLogAnalyzer(runtime.GOOS)
	if !ok {
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return initializer()
}
