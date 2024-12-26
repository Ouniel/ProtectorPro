//go:build linux
package process

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "syscall"
    "time"
)

type linuxProcessAnalyzer struct{}

func init() {
    registerProcessAnalyzer("linux", func() (ProcessAnalyzer, error) {
        return &linuxProcessAnalyzer{}, nil
    })
}

func (l *linuxProcessAnalyzer) GetProcessList() ([]ProcessInfo, error) {
    var processes []ProcessInfo
    
    // Read /proc directory
    files, err := ioutil.ReadDir("/proc")
    if err != nil {
        return nil, fmt.Errorf("failed to read /proc: %v", err)
    }
    
    for _, f := range files {
        // Check if the file name is a number (PID)
        if pid, err := strconv.Atoi(f.Name()); err == nil {
            if info, err := l.GetProcessByPID(pid); err == nil {
                processes = append(processes, *info)
            }
        }
    }
    
    return processes, nil
}

func (l *linuxProcessAnalyzer) GetProcessByPID(pid int) (*ProcessInfo, error) {
    info := &ProcessInfo{PID: pid}
    
    // Read process status
    status, err := l.readProcFile(pid, "status")
    if err != nil {
        return nil, err
    }
    
    // Parse status file
    scanner := bufio.NewScanner(strings.NewReader(status))
    for scanner.Scan() {
        line := scanner.Text()
        parts := strings.SplitN(line, ":", 2)
        if len(parts) != 2 {
            continue
        }
        
        key := strings.TrimSpace(parts[0])
        value := strings.TrimSpace(parts[1])
        
        switch key {
        case "Name":
            info.Name = value
        case "State":
            info.Status = value
        }
    }
    
    // Read command line
    if cmdline, err := l.readProcFile(pid, "cmdline"); err == nil {
        info.CommandLine = strings.Replace(cmdline, "\x00", " ", -1)
    }
    
    // Get process start time
    if stat, err := l.readProcFile(pid, "stat"); err == nil {
        fields := strings.Fields(stat)
        if len(fields) > 21 {
            if startTime, err := strconv.ParseInt(fields[21], 10, 64); err == nil {
                info.StartTime = time.Unix(startTime/100, 0)
            }
        }
    }
    
    return info, nil
}

func (l *linuxProcessAnalyzer) KillProcess(pid int32) error {
    proc, err := os.FindProcess(int(pid))
    if err != nil {
        return fmt.Errorf("failed to find process: %v", err)
    }
    
    return proc.Signal(syscall.SIGTERM)
}

func (l *linuxProcessAnalyzer) readProcFile(pid int, name string) (string, error) {
    path := filepath.Join("/proc", strconv.Itoa(pid), name)
    data, err := ioutil.ReadFile(path)
    if err != nil {
        return "", fmt.Errorf("failed to read %s: %v", path, err)
    }
    return string(data), nil
}
