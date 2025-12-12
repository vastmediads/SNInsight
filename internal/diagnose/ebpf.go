//go:build linux

package diagnose

// RunEBPFDiagnose 运行 eBPF 诊断（JSON 格式输出）
func RunEBPFDiagnose() *DiagnoseReport {
	report := NewDiagnoseReport("ebpf")
	report.System = CollectSystemInfo()

	// 收集各项检查
	kernel := collectKernelInfo()
	bpfCfg := collectBPFConfig()
	security := collectSecurityInfo()
	perms := collectPermissions()
	btf := collectBTFInfo()

	// 1. 内核检查
	report.AddCheckWithDetails("kernel", StatusPass,
		kernel.Version, map[string]any{"arch": kernel.Arch})

	// 2. BPF 配置检查
	switch bpfCfg.UnprivilegedBPFDisabled {
	case 0:
		report.AddCheck("unprivileged_bpf", StatusPass, "允许非特权用户使用 BPF")
	case 1:
		report.AddCheck("unprivileged_bpf", StatusPass, "仅 root 可使用 BPF (正常)")
	case 2:
		report.AddCheck("unprivileged_bpf", StatusFail, "BPF 已被完全禁用 (建议设为 0 或 1)")
	default:
		report.AddCheck("unprivileged_bpf", StatusWarning,
			"无法读取 unprivileged_bpf_disabled")
	}

	// 3. JIT 检查
	if bpfCfg.BPFJITEnable >= 1 {
		report.AddCheck("bpf_jit", StatusPass, "BPF JIT 已启用")
	} else if bpfCfg.BPFJITEnable == 0 {
		report.AddCheck("bpf_jit", StatusWarning, "BPF JIT 未启用 (可能影响性能)")
	} else {
		report.AddCheck("bpf_jit", StatusWarning, "无法读取 BPF JIT 状态")
	}

	// 4. 安全模块检查
	if security.Lockdown != "" && security.Lockdown != "未启用" {
		if containsLockdown(security.Lockdown, "integrity") ||
			containsLockdown(security.Lockdown, "confidentiality") {
			report.AddCheck("lockdown", StatusWarning,
				"Kernel Lockdown 已启用: "+security.Lockdown)
		} else {
			report.AddCheck("lockdown", StatusPass, "Kernel Lockdown: "+security.Lockdown)
		}
	} else {
		report.AddCheck("lockdown", StatusPass, "Kernel Lockdown 未启用")
	}

	// 5. SELinux 检查
	if security.SELinux == "enforcing" {
		report.AddCheck("selinux", StatusWarning,
			"SELinux 为 enforcing 模式，可能阻止 eBPF")
	} else {
		report.AddCheck("selinux", StatusPass, "SELinux: "+security.SELinux)
	}

	// 6. 权限检查
	if perms.EUID == 0 {
		report.AddCheck("permissions", StatusPass, "以 root 权限运行")
	} else if perms.HasBPF && perms.HasAdmin {
		report.AddCheck("permissions", StatusPass, "具有 CAP_BPF 和 CAP_SYS_ADMIN")
	} else {
		report.AddCheck("permissions", StatusFail,
			"权限不足，需要 root 或 CAP_BPF+CAP_SYS_ADMIN")
	}

	// 7. BTF 检查
	if btf.VmlinuxExists {
		report.AddCheck("btf", StatusPass, "BTF vmlinux 存在: "+btf.VmlinuxPath)
	} else {
		report.AddCheck("btf", StatusFail,
			"BTF vmlinux 不存在，eBPF CO-RE 可能无法工作")
	}

	// 8. 网卡检查
	ifaces := collectInterfaces()
	upCount := 0
	for _, iface := range ifaces {
		if iface.Status == "UP" {
			upCount++
		}
	}
	if upCount > 0 {
		report.AddCheckWithDetails("interfaces", StatusPass,
			"发现可用网卡", map[string]any{"up_count": upCount, "total": len(ifaces)})
	} else {
		report.AddCheck("interfaces", StatusFail, "没有发现处于 UP 状态的网卡")
	}

	// 生成摘要
	generateEBPFSummary(report)

	return report
}

func containsLockdown(lockdown, mode string) bool {
	// lockdown 格式可能是 "[none] integrity confidentiality"
	// 当前模式用 [] 包裹
	return len(lockdown) > 0 && lockdown[0] == '[' && lockdown != "[none]"
}

func generateEBPFSummary(report *DiagnoseReport) {
	failCount := 0
	warnCount := 0

	for _, check := range report.Checks {
		switch check.Status {
		case StatusFail:
			failCount++
		case StatusWarning:
			warnCount++
		}
	}

	if failCount == 0 && warnCount == 0 {
		report.SetSummary("所有检查通过，eBPF 环境正常")
	} else if failCount == 0 {
		report.SetSummary("eBPF 环境基本正常，有 " + string(rune('0'+warnCount)) + " 项警告")
	} else {
		report.SetSummary("eBPF 环境存在问题，请检查失败项")
	}
}
