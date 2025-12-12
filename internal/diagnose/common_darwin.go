//go:build darwin

package diagnose

import (
	"encoding/json"
	"os"
	"time"
)

// CheckStatus 检查状态
type CheckStatus string

const (
	StatusPass    CheckStatus = "pass"
	StatusFail    CheckStatus = "fail"
	StatusWarning CheckStatus = "warning"
	StatusSkipped CheckStatus = "skipped"
)

// CheckResult 单项检查结果
type CheckResult struct {
	Name    string      `json:"name"`
	Status  CheckStatus `json:"status"`
	Message string      `json:"message,omitempty"`
	Error   string      `json:"error,omitempty"`
	Details any         `json:"details,omitempty"`
}

// DiagnoseReport 诊断报告（JSON 格式）
type DiagnoseReport struct {
	Timestamp time.Time     `json:"timestamp"`
	Type      string        `json:"type"`
	Status    CheckStatus   `json:"status"`
	Summary   string        `json:"summary"`
	Checks    []CheckResult `json:"checks"`
	System    *SystemInfo   `json:"system,omitempty"`
}

// SystemInfo 系统信息
type SystemInfo struct {
	Kernel      string   `json:"kernel"`
	Arch        string   `json:"arch"`
	Hostname    string   `json:"hostname"`
	Interfaces  []string `json:"interfaces,omitempty"`
	UID         int      `json:"uid"`
	EUID        int      `json:"euid"`
	HasCapBPF   bool     `json:"has_cap_bpf"`
	HasCapAdmin bool     `json:"has_cap_admin"`
}

// NewDiagnoseReport 创建诊断报告
func NewDiagnoseReport(reportType string) *DiagnoseReport {
	return &DiagnoseReport{
		Timestamp: time.Now(),
		Type:      reportType,
		Status:    StatusPass,
		Checks:    make([]CheckResult, 0),
	}
}

// AddCheck 添加检查结果
func (r *DiagnoseReport) AddCheck(name string, status CheckStatus, message string) {
	r.Checks = append(r.Checks, CheckResult{
		Name:    name,
		Status:  status,
		Message: message,
	})
	r.updateOverallStatus(status)
}

func (r *DiagnoseReport) updateOverallStatus(status CheckStatus) {
	if status == StatusFail {
		r.Status = StatusFail
	} else if status == StatusWarning && r.Status != StatusFail {
		r.Status = StatusWarning
	}
}

// SetSummary 设置摘要
func (r *DiagnoseReport) SetSummary(summary string) {
	r.Summary = summary
}

// OutputJSON 输出 JSON 格式
func (r *DiagnoseReport) OutputJSON() error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// CollectSystemInfo 收集系统信息（macOS 简化版）
func CollectSystemInfo() *SystemInfo {
	hostname, _ := os.Hostname()
	return &SystemInfo{
		Kernel:   "macOS",
		Arch:     "arm64",
		Hostname: hostname,
		UID:      os.Getuid(),
		EUID:     os.Geteuid(),
	}
}
