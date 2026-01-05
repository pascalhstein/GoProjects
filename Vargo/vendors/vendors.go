package vendors

import (
	"bufio"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

const (
	databaseURL = "https://www.wireshark.org/download/automated/data/manuf"
	fileName    = "manuf.txt"
)

var (
	vendorMap map[string]string
	once      sync.Once
)

func DownloadVendorsList() error {
	resp, err := http.Get(databaseURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func LoadVendors() {
	once.Do(func() {
		vendorMap = make(map[string]string)
		
		file, err := os.Open(fileName)
		if err != nil {
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 2 {
				prefix := strings.ReplaceAll(parts[0], ":", "")
				if len(prefix) == 6 {
					vendorMap[strings.ToUpper(prefix)] = parts[1]
				}
			}
		}
	})
}

func LookupVendor(mac string) string {
    LoadVendors()

    cleanMac := strings.ReplaceAll(mac, ":", "")
    cleanMac = strings.ReplaceAll(cleanMac, "-", "")
    cleanMac = strings.ReplaceAll(cleanMac, ".", "")
    cleanMac = strings.ToUpper(strings.TrimSpace(cleanMac))

    if len(cleanMac) < 6 {
        return "Unknown Device"
    }

    prefix := cleanMac[:6]
    
    if vendor, exists := vendorMap[prefix]; exists {
        return vendor
    }

    return "Unknown Vendor"
}