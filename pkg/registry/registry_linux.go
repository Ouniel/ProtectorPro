//go:build linux
package registry

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "time"
)

// Linux system configuration paths
const (
    etcPath = "/etc"
    sysPath = "/sys"
    procPath = "/proc"
)

type linuxRegistryAnalyzer struct{}

func init() {
    registerRegistryAnalyzer("linux", func() (RegistryAnalyzer, error) {
        return &linuxRegistryAnalyzer{}, nil
    })
}

func (l *linuxRegistryAnalyzer) GetKeyInfo(path string) (*RegistryKey, error) {
    // Convert Windows-style path to Linux path
    linuxPath := l.convertPath(path)
    
    info := &RegistryKey{
        Path: linuxPath,
    }
    
    // Get file info
    fileInfo, err := os.Stat(linuxPath)
    if err != nil {
        return nil, fmt.Errorf("failed to get file info: %v", err)
    }
    
    info.LastWrite = fileInfo.ModTime().Format(time.RFC3339)
    
    // Get subkeys (directories)
    if fileInfo.IsDir() {
        files, err := ioutil.ReadDir(linuxPath)
        if err != nil {
            return nil, fmt.Errorf("failed to read directory: %v", err)
        }
        
        for _, f := range files {
            if f.IsDir() {
                info.SubKeys = append(info.SubKeys, f.Name())
            }
        }
    }
    
    // Get values (file contents)
    values, err := l.EnumerateValues(path)
    if err == nil {
        info.Values = values
    }
    
    return info, nil
}

func (l *linuxRegistryAnalyzer) GetValue(keyPath, valueName string) (*RegistryValue, error) {
    linuxPath := l.convertPath(keyPath)
    filePath := filepath.Join(linuxPath, valueName)
    
    data, err := ioutil.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %v", err)
    }
    
    return &RegistryValue{
        Name: valueName,
        Type: "REG_SZ",
        Data: strings.TrimSpace(string(data)),
    }, nil
}

func (l *linuxRegistryAnalyzer) EnumerateKeys(path string) ([]string, error) {
    linuxPath := l.convertPath(path)
    
    files, err := ioutil.ReadDir(linuxPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read directory: %v", err)
    }
    
    var keys []string
    for _, f := range files {
        if f.IsDir() {
            keys = append(keys, f.Name())
        }
    }
    
    return keys, nil
}

func (l *linuxRegistryAnalyzer) EnumerateValues(path string) ([]RegistryValue, error) {
    linuxPath := l.convertPath(path)
    
    files, err := ioutil.ReadDir(linuxPath)
    if err != nil {
        return nil, fmt.Errorf("failed to read directory: %v", err)
    }
    
    var values []RegistryValue
    for _, f := range files {
        if !f.IsDir() {
            data, err := ioutil.ReadFile(filepath.Join(linuxPath, f.Name()))
            if err == nil {
                values = append(values, RegistryValue{
                    Name: f.Name(),
                    Type: "REG_SZ",
                    Data: strings.TrimSpace(string(data)),
                })
            }
        }
    }
    
    return values, nil
}

// convertPath converts a Windows-style registry path to a Linux filesystem path
func (l *linuxRegistryAnalyzer) convertPath(path string) string {
    // Remove HKEY_ prefix
    path = strings.TrimPrefix(path, "HKEY_LOCAL_MACHINE\\")
    path = strings.TrimPrefix(path, "HKEY_CURRENT_USER\\")
    
    // Convert backslashes to forward slashes
    path = strings.ReplaceAll(path, "\\", "/")
    
    // Map common Windows registry paths to Linux paths
    switch {
    case strings.HasPrefix(path, "SYSTEM/CurrentControlSet/Services"):
        return filepath.Join(etcPath, "systemd/system")
    case strings.HasPrefix(path, "SOFTWARE/Microsoft/Windows/CurrentVersion/Run"):
        return filepath.Join(etcPath, "xdg/autostart")
    case strings.HasPrefix(path, "SYSTEM/CurrentControlSet/Control/TimeZoneInformation"):
        return filepath.Join(etcPath, "timezone")
    case strings.HasPrefix(path, "SYSTEM/CurrentControlSet/Control/NetworkSetup2"):
        return filepath.Join(etcPath, "network")
    default:
        // Default to /etc for system configuration
        return filepath.Join(etcPath, path)
    }
}
