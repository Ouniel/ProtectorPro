//go:build linux
package network

import (
    "bufio"
    "fmt"
    "io/ioutil"
    "net"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "time"
)

type linuxNetworkAnalyzer struct{}

func init() {
    registerNetworkAnalyzer("linux", func() (NetworkAnalyzer, error) {
        return &linuxNetworkAnalyzer{}, nil
    })
}

func (l *linuxNetworkAnalyzer) GetConnections() ([]ConnectionInfo, error) {
    var connections []ConnectionInfo
    
    // Read TCP connections
    tcpConns, err := l.readProcNet("tcp")
    if err != nil {
        return nil, err
    }
    connections = append(connections, tcpConns...)
    
    // Read TCP6 connections
    tcp6Conns, err := l.readProcNet("tcp6")
    if err != nil {
        return nil, err
    }
    connections = append(connections, tcp6Conns...)
    
    // Read UDP connections
    udpConns, err := l.readProcNet("udp")
    if err != nil {
        return nil, err
    }
    connections = append(connections, udpConns...)
    
    // Read UDP6 connections
    udp6Conns, err := l.readProcNet("udp6")
    if err != nil {
        return nil, err
    }
    connections = append(connections, udp6Conns...)
    
    return connections, nil
}

func (l *linuxNetworkAnalyzer) GetConnectionsByPID(pid int32) ([]ConnectionInfo, error) {
    allConns, err := l.GetConnections()
    if err != nil {
        return nil, err
    }
    
    var pidConns []ConnectionInfo
    for _, conn := range allConns {
        if conn.PID == pid {
            pidConns = append(pidConns, conn)
        }
    }
    
    return pidConns, nil
}

func (l *linuxNetworkAnalyzer) GetListeningPorts() ([]ConnectionInfo, error) {
    allConns, err := l.GetConnections()
    if err != nil {
        return nil, err
    }
    
    var listening []ConnectionInfo
    for _, conn := range allConns {
        if conn.State == "LISTEN" {
            listening = append(listening, conn)
        }
    }
    
    return listening, nil
}

func (l *linuxNetworkAnalyzer) readProcNet(proto string) ([]ConnectionInfo, error) {
    path := filepath.Join("/proc/net", proto)
    file, err := os.Open(path)
    if err != nil {
        return nil, fmt.Errorf("failed to open %s: %v", path, err)
    }
    defer file.Close()
    
    var connections []ConnectionInfo
    scanner := bufio.NewScanner(file)
    
    // Skip header line
    scanner.Scan()
    
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)
        if len(fields) < 10 {
            continue
        }
        
        localAddr, localPort := l.parseAddress(fields[1])
        remoteAddr, remotePort := l.parseAddress(fields[2])
        state := l.parseState(fields[3])
        inode := fields[9]
        
        pid := l.findPIDByInode(inode)
        processName := ""
        if pid > 0 {
            if name, err := l.getProcessName(int32(pid)); err == nil {
                processName = name
            }
        }
        
        conn := ConnectionInfo{
            Protocol:    proto,
            LocalAddr:   localAddr,
            LocalPort:   localPort,
            RemoteAddr:  remoteAddr,
            RemotePort:  remotePort,
            State:      state,
            PID:        int32(pid),
            ProcessName: processName,
            StartTime:  time.Now(), // Note: actual start time is not available in /proc/net
        }
        
        connections = append(connections, conn)
    }
    
    return connections, nil
}

func (l *linuxNetworkAnalyzer) parseAddress(hexAddr string) (string, uint16) {
    parts := strings.Split(hexAddr, ":")
    if len(parts) != 2 {
        return "", 0
    }
    
    // Convert hex address to IP
    addrBytes := make([]byte, 4)
    fmt.Sscanf(parts[0], "%08x", &addrBytes)
    ip := net.IPv4(addrBytes[3], addrBytes[2], addrBytes[1], addrBytes[0])
    
    // Convert hex port to uint16
    port, _ := strconv.ParseUint(parts[1], 16, 16)
    
    return ip.String(), uint16(port)
}

func (l *linuxNetworkAnalyzer) parseState(hexState string) string {
    states := map[string]string{
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    
    if state, ok := states[hexState]; ok {
        return state
    }
    return "UNKNOWN"
}

func (l *linuxNetworkAnalyzer) findPIDByInode(inode string) int {
    files, err := ioutil.ReadDir("/proc")
    if err != nil {
        return 0
    }
    
    for _, f := range files {
        if pid, err := strconv.Atoi(f.Name()); err == nil {
            fdPath := filepath.Join("/proc", f.Name(), "fd")
            fds, err := ioutil.ReadDir(fdPath)
            if err != nil {
                continue
            }
            
            for _, fd := range fds {
                link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
                if err != nil {
                    continue
                }
                
                if strings.Contains(link, "socket:["+inode+"]") {
                    return pid
                }
            }
        }
    }
    
    return 0
}

func (l *linuxNetworkAnalyzer) getProcessName(pid int32) (string, error) {
    data, err := ioutil.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "comm"))
    if err != nil {
        return "", err
    }
    return strings.TrimSpace(string(data)), nil
}
