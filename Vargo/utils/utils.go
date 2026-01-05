package utils

import (
	"fmt"
    "net"
)

func GetLocalSubnet() (string, error) {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return "", err
    }
    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipnet.IP.To4() != nil {
                return ipnet.String(), nil
            }
        }
    }
    return "", fmt.Errorf("Could not determine local subnet")
}

func CountIPsInCIDR(cidr string) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}
	ones, bits := ipnet.Mask.Size()
	return 1 << (bits - ones)
}