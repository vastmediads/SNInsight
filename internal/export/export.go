package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/nickproject/sninsight/internal/aggregator"
)

// ExportFormat 导出格式
type ExportFormat string

const (
	FormatJSON ExportFormat = "json"
	FormatCSV  ExportFormat = "csv"
)

// Report 导出报告
type Report struct {
	Timestamp   time.Time               `json:"timestamp"`
	Duration    time.Duration           `json:"duration"`
	TotalIn     uint64                  `json:"total_in_bytes"`
	TotalOut    uint64                  `json:"total_out_bytes"`
	Connections int                     `json:"connections"`
	Entries     []aggregator.TrafficEntry `json:"entries"`
}

// Export 导出数据到文件
func Export(report *Report, filename string, format ExportFormat) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	defer file.Close()

	switch format {
	case FormatJSON:
		return exportJSON(report, file)
	case FormatCSV:
		return exportCSV(report, file)
	default:
		return fmt.Errorf("不支持的格式: %s", format)
	}
}

func exportJSON(report *Report, file *os.File) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func exportCSV(report *Report, file *os.File) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入头部
	headers := []string{
		"domain_ip",
		"protocol",
		"in_rate_bytes_s",
		"out_rate_bytes_s",
		"total_in_bytes",
		"total_out_bytes",
		"connections",
	}
	if err := writer.Write(headers); err != nil {
		return err
	}

	// 写入数据行
	for _, entry := range report.Entries {
		row := []string{
			entry.DisplayName,
			entry.Protocol,
			fmt.Sprintf("%d", entry.InRate),
			fmt.Sprintf("%d", entry.OutRate),
			fmt.Sprintf("%d", entry.TotalIn),
			fmt.Sprintf("%d", entry.TotalOut),
			fmt.Sprintf("%d", entry.ConnCount),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// ParseFormat 解析格式字符串
func ParseFormat(s string) (ExportFormat, error) {
	switch s {
	case "json", "JSON":
		return FormatJSON, nil
	case "csv", "CSV":
		return FormatCSV, nil
	default:
		return "", fmt.Errorf("不支持的格式: %s (支持: json, csv)", s)
	}
}
