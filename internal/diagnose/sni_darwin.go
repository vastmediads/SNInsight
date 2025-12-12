//go:build darwin

package diagnose

// RunSNIDiagnose 在 macOS 上返回不支持的报告
func RunSNIDiagnose(testDomain string) *DiagnoseReport {
	report := NewDiagnoseReport("sni")
	report.System = CollectSystemInfo()
	report.AddCheck("platform", StatusFail, "SNI 诊断仅支持 Linux 平台")
	report.SetSummary("macOS 不支持 eBPF SNI 捕获，请在 Linux 上运行诊断")
	return report
}
