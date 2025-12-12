//go:build linux

package diagnose

import (
	"encoding/json"
	"fmt"
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
	Type      string        `json:"type"` // "ebpf" 或 "sni"
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

// AddCheckWithError 添加带错误的检查结果
func (r *DiagnoseReport) AddCheckWithError(name string, status CheckStatus, message string, err error) {
	check := CheckResult{
		Name:    name,
		Status:  status,
		Message: message,
	}
	if err != nil {
		check.Error = err.Error()
	}
	r.Checks = append(r.Checks, check)
	r.updateOverallStatus(status)
}

// AddCheckWithDetails 添加带详细信息的检查结果
func (r *DiagnoseReport) AddCheckWithDetails(name string, status CheckStatus, message string, details any) {
	r.Checks = append(r.Checks, CheckResult{
		Name:    name,
		Status:  status,
		Message: message,
		Details: details,
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

// OutputJSONToFile 输出 JSON 到文件
func (r *DiagnoseReport) OutputJSONToFile(filepath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0644)
}

// CollectSystemInfo 收集系统信息
func CollectSystemInfo() *SystemInfo {
	hostname, _ := os.Hostname()
	kernel := collectKernelInfo()
	perms := collectPermissions()
	ifaces := collectInterfaces()

	ifaceNames := make([]string, 0, len(ifaces))
	for _, iface := range ifaces {
		ifaceNames = append(ifaceNames, fmt.Sprintf("%s(%s)", iface.Name, iface.Status))
	}

	return &SystemInfo{
		Kernel:      kernel.Version,
		Arch:        kernel.Arch,
		Hostname:    hostname,
		Interfaces:  ifaceNames,
		UID:         perms.UID,
		EUID:        perms.EUID,
		HasCapBPF:   perms.HasBPF,
		HasCapAdmin: perms.HasAdmin,
	}
}
