package export 

import (
	"os"
	"encoding/csv"
	"strings"
	"fmt"
)

func ExportResults(filename string, data [][]string) error {
    file, err := os.Create(filename)
    if err != nil {
        return err
    }
    defer file.Close()

    if strings.HasSuffix(strings.ToLower(filename), ".csv") {
        writer := csv.NewWriter(file)
        writer.Comma = ';'
        defer writer.Flush()
        return writer.WriteAll(data)
    } else {
        for _, line := range data {
            _, err := fmt.Fprintln(file, strings.Join(line, " | "))
            if err != nil {
                return err
            }
        }
    }
    return nil
}