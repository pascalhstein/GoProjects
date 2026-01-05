package main

import (
	"flag"
	"fmt"
	"time"
	"math/rand"

	"go-netscan/pingworker"
	"go-netscan/utils"
	"go-netscan/export"
	"go-netscan/vendors"

	"github.com/pterm/pterm"
)

func main() {
    // setting the flags
    workerCount := flag.Int("w", 200, "Concurrent workers")
    netRange := flag.String("n", "", "Network range (e.g., 192.168.1.0/24)")
    checkPorts := flag.String("cp", "default", "Ports to check")
    exportResults := flag.String("o", "", "Export file (e.g., results.csv)")
    updateVendors := flag.Bool("uv", false, "Update MAC database")
    skipVendorLookup := flag.Bool("sv", false, "Skip MAC lookup")
    skipHostnameLookup := flag.Bool("sh", false, "Skip Hostname lookup")
	skipPortScan := flag.Bool("sp", false, "Skip Port Scan")	
    flag.Parse()

    // shwoing header information in cli
    pterm.DefaultHeader.WithFullWidth().
        WithBackgroundStyle(pterm.NewStyle(pterm.BgCyan)).
        WithTextStyle(pterm.NewStyle(pterm.FgBlack)).
        Println(" VARGO v1.0 | High-Speed Network Discovery ")

    if *netRange == "" {
        local, err := utils.GetLocalSubnet()
        if err != nil {
            pterm.Error.Println("Please specify network range with -n")
            return
        }
        *netRange = local
    }

    // Get the vendor list
    if *updateVendors {
        pterm.Info.Println("Updating MAC vendor database...")
        vendors.DownloadVendorsList()
    }
    vendors.LoadVendors()

    // show a progressbar while scanning
    numIps := utils.CountIPsInCIDR(*netRange)
    progress, _ := pterm.DefaultProgressbar.
        WithTotal(numIps).
        Start()
    
    // activeHosts contains all found hosts
    var activeHosts [][]string
    start := time.Now()

    // 5. Start the ping workers and collect results
    resultsChan := pingworker.StartPingWorkers(*workerCount, *netRange, pingworker.ParsePorts(*checkPorts), *skipHostnameLookup, *skipPortScan)
    localArpCache := pingworker.GetFullARPCache()

    for res := range resultsChan {
        progress.Increment()

        if res.IsUp {
            pterm.Success.Printf(" Found active host: %s\n", res.IP)

            vendorName := "Unknown"
            if !*skipVendorLookup {
                mac := localArpCache[res.IP]
                if mac != "" {
                    vendorName = vendors.LookupVendor(mac)
                }
            }

            // the result is appended to the activeHosts slice
            activeHosts = append(activeHosts, []string{
                pterm.LightBlue(res.IP),
                pterm.LightYellow(res.Hostname),
                vendorName,
                pterm.LightGreen(fmt.Sprintf("%v", res.OpenPorts)),
            })
        }
    }

    progress.Stop()
    fmt.Println()

    tableData := pterm.TableData{
        {"IP-Adresse", "Hostname", "Vendor", "Open Ports"},
    }

    if len(activeHosts) > 0 {
        tableData = append(tableData, activeHosts...)
        
        pterm.DefaultSection.Println("Scan Summary")
        pterm.DefaultTable.
            WithHasHeader().
            WithData(tableData).
            WithBoxed().
            Render()
    } else {
        pterm.Warning.Println("No active devices found in the specified range.")
    }

    duration := time.Since(start)
    pterm.Info.Printf("Scan duration: %s\n", duration.Round(time.Millisecond))

    if *exportResults != "" {
        err := export.ExportResults(*exportResults, tableData)
        if err != nil {
            pterm.Error.Printf("Export error: %v\n", err)
        } else {
            pterm.Success.Printf("Results saved to: %s\n", *exportResults)
        }
    }
}

func returnSpinnerSuccessText() string {
	successTexts := []string{
		"Vargo has returned from the digital abyss!",
		"Network charted. No Gophers were harmed.",
		"Scan complete. All secrets have been extracted.",
		"Inventory complete. Even the silent ones were found.",
		"Vargo successfully unmasked the targets!",
		"Mission accomplished. The subnet has no more hiding spots.",
		"Data secured. Vargo is heading back to the shadows.",
		"Done! Vargo out-performed the intern again.",
		"Target acquisition finalized. Report is ready.",
		"All bits and bytes aligned perfectly!",
	}

	return successTexts[rand.Intn(len(successTexts))]
}