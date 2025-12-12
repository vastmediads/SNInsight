//go:build darwin

package diagnose

// RunEBPFDiagnose 在 macOS 上返回不支持的报告
func RunEBPFDiagnose() *DiagnoseReport {
	report := NewDiagnoseReport("ebpf")
	report.System = CollectSystemInfo()
	report.AddCheck("platform", StatusFail, "eBPF 诊断仅支持 Linux 平台")
	report.SetSummary("macOS 不支持 eBPF，请在 Linux 上运行诊断")
	return report
}
