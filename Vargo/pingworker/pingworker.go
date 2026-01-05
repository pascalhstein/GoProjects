package pingworker

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
	"fmt"
	"regexp"
)

type ScanResult struct {
	IP       string
	Hostname string
	IsUp     bool
	MacAddress string
	Latency  time.Duration
	OpenPorts []PortInfo 
}

// Starts the ping workers and returns a channel with results
func StartPingWorkers(workerCount int, cidr string, ports []PortInfo, skipHostnameLookup bool, skipPortScan bool) chan ScanResult {
	ips, err := resolveCIDR(cidr)
	if err != nil {
		return nil
	}

	// create the results channel
	results := make(chan ScanResult)

    // start the worker goroutine
	go func() {

		// the workerpool contains the workers
        var wg sync.WaitGroup
        jobs := make(chan string, len(ips))

		// start a new goroutine for each worker
        for i := 0; i < workerCount; i++ {
            // add the waitgroup counter
            wg.Add(1)
            go func() {
                // actual function that each worker runs
                defer wg.Done()
                for ip := range jobs {
					start := time.Now()
					if reachable := Ping(ip); reachable {
						elapsed := time.Since(start)
						res := ScanResult{
							IP:      ip, 
							IsUp:    true, 
							Latency: elapsed,
						}

						if !skipHostnameLookup {
							names, _ := net.LookupAddr(ip)
							if len(names) > 0 {
								res.Hostname = strings.TrimSuffix(names[0], ".")
							}
						}

						if !skipPortScan {
							for _, p := range ports {
								if CheckPort(ip, p.Number, 500*time.Millisecond) {
									res.OpenPorts = append(res.OpenPorts, p)
								}
							}
						}
						results <- res
					}
				}
            }()
        }

        // add each IP to the jobs channel
        for _, ip := range ips { jobs <- ip }
        close(jobs)
        wg.Wait()
        close(results)
    }()

    return results
}

func resolveCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func Ping(ip string) bool {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "500", ip)
	case "darwin", "linux":
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	default:
		return false
	}

	err := cmd.Run()
	return err == nil
}

func CheckPort(ip string, port int, timeout time.Duration) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

type PortInfo struct {
    Number int
    Name   string
}

func ParsePorts(input string) []PortInfo {
    var results []PortInfo

    getProto := func(p int) PortInfo {
        name, exists := portNames[p]
        if !exists {
            name = "Unknown"
        }
        return PortInfo{Number: p, Name: name}
    }

    if input == "default" {
        defaultPorts := []int{21, 22, 80, 443, 445, 3389}
        for _, p := range defaultPorts {
            results = append(results, getProto(p))
        }
        return results
    }

    parts := strings.Split(input, ",")
    for _, p := range parts {
        p = strings.TrimSpace(strings.ToLower(p))
        
        if portNum, exists := commonPorts[p]; exists {
            results = append(results, getProto(portNum))
        } else {
            var portNum int
            _, err := fmt.Sscanf(p, "%d", &portNum)
            if err == nil && portNum > 0 {
                results = append(results, getProto(portNum))
            }
        }
    }
    return results
}

var commonPorts = map[string]int{
    "ftp":    21,
    "ssh":    22,
    "telnet": 23,
    "smtp":   25,
    "dns":    53,
    "http":   80,
    "https":  443,
    "smb":    445,
    "mysql":  3306,
    "rdp":    3389,
    "docker": 2375,
}

var portNames = map[int]string{
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
}

func GetFullARPCache() map[string]string {
    macMap := make(map[string]string)
    var cmd *exec.Cmd

    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("powershell", "-Command", "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress, LinkLayerAddress")
    case "darwin":
        cmd = exec.Command("arp", "-an")
    case "linux":
        cmd = exec.Command("arp", "-n")
    default:
        cmd = exec.Command("arp", "-a")
    }

    out, err := cmd.Output()
    if err != nil {
        out, _ = exec.Command("arp", "-a").Output()
    }

    re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?([0-9A-Fa-f]{1,2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})`)
    matches := re.FindAllStringSubmatch(string(out), -1)

    for _, match := range matches {
        if len(match) >= 3 {
            ip := match[1]
            mac := strings.ReplaceAll(match[2], "-", ":")
            macMap[ip] = strings.ToUpper(mac)
        }
    }
    return macMap
}