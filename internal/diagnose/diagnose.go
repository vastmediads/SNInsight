//go:build linux

package diagnose

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DiagReport 诊断报告
type DiagReport struct {
	Timestamp   time.Time
	Error       string
	Kernel      KernelInfo
	BPFConfig   BPFConfigInfo
	Security    SecurityInfo
	Permissions PermissionInfo
	BTF         BTFInfo
	LoadedProgs []BPFProgInfo
	Interfaces  []NetInterface
}

// KernelInfo 内核信息
type KernelInfo struct {
	Version string
	Arch    string
}

// BPFConfigInfo BPF 配置信息
type BPFConfigInfo struct {
	UnprivilegedBPFDisabled int    // /proc/sys/kernel/unprivileged_bpf_disabled
	BPFJITEnable            int    // /proc/sys/net/core/bpf_jit_enable
	RawUnprivileged         string // 原始值
	RawJIT                  string // 原始值
}

// SecurityInfo 安全模块信息
type SecurityInfo struct {
	LSM      string // /sys/kernel/security/lsm
	Lockdown string // /sys/kernel/security/lockdown
	SELinux  string // SELinux 状态
	AppArmor string // AppArmor 状态
}

// PermissionInfo 权限信息
type PermissionInfo struct {
	UID      int
	EUID     int
	CapEff   string // 有效 capabilities
	HasBPF   bool   // CAP_BPF
	HasAdmin bool   // CAP_SYS_ADMIN
}

// BTFInfo BTF 支持信息
type BTFInfo struct {
	VmlinuxExists bool
	VmlinuxPath   string
}

// BPFProgInfo 已加载的 BPF 程序信息
type BPFProgInfo struct {
	ID   string
	Type string
	Name string
}

// NetInterface 网卡信息
type NetInterface struct {
	Name   string
	Status string
	Addrs  []string
}

// Collect 收集诊断信息
func Collect(err error) *DiagReport {
	report := &DiagReport{
		Timestamp: time.Now(),
	}

	if err != nil {
		report.Error = err.Error()
	}

	report.Kernel = collectKernelInfo()
	report.BPFConfig = collectBPFConfig()
	report.Security = collectSecurityInfo()
	report.Permissions = collectPermissions()
	report.BTF = collectBTFInfo()
	report.LoadedProgs = collectLoadedProgs()
	report.Interfaces = collectInterfaces()

	return report
}

// Output 输出诊断报告（stderr + 文件）
func Output(report *DiagReport) string {
	// 输出到 stderr
	outputToStderr(report)

	// 保存到文件
	filePath := saveToFile(report)

	return filePath
}

// collectKernelInfo 收集内核信息
func collectKernelInfo() KernelInfo {
	info := KernelInfo{
		Arch: runtime.GOARCH,
	}

	data, err := os.ReadFile("/proc/version")
	if err == nil {
		info.Version = strings.TrimSpace(string(data))
	} else {
		info.Version = "unknown"
	}

	return info
}

// collectBPFConfig 收集 BPF 配置
func collectBPFConfig() BPFConfigInfo {
	cfg := BPFConfigInfo{
		UnprivilegedBPFDisabled: -1,
		BPFJITEnable:            -1,
	}

	// unprivileged_bpf_disabled
	if data, err := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil {
		cfg.RawUnprivileged = strings.TrimSpace(string(data))
		cfg.UnprivilegedBPFDisabled, _ = strconv.Atoi(cfg.RawUnprivileged)
	}

	// bpf_jit_enable
	if data, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable"); err == nil {
		cfg.RawJIT = strings.TrimSpace(string(data))
		cfg.BPFJITEnable, _ = strconv.Atoi(cfg.RawJIT)
	}

	return cfg
}

// collectSecurityInfo 收集安全模块信息
func collectSecurityInfo() SecurityInfo {
	info := SecurityInfo{}

	// LSM
	if data, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		info.LSM = strings.TrimSpace(string(data))
	} else {
		info.LSM = "无法读取"
	}

	// Lockdown
	if data, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil {
		content := strings.TrimSpace(string(data))
		// 格式可能是 "[none] integrity confidentiality" 或类似
		info.Lockdown = content
	} else {
		info.Lockdown = "未启用"
	}

	// SELinux
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			info.SELinux = "enforcing"
		} else {
			info.SELinux = "permissive"
		}
	} else {
		info.SELinux = "未启用"
	}

	// AppArmor
	if output, err := exec.Command("aa-status", "--enabled").Output(); err == nil {
		if strings.Contains(string(output), "Yes") {
			info.AppArmor = "启用"
		} else {
			info.AppArmor = "未启用"
		}
	} else {
		// 尝试读取 /sys/module/apparmor
		if _, err := os.Stat("/sys/module/apparmor"); err == nil {
			info.AppArmor = "已加载"
		} else {
			info.AppArmor = "未安装"
		}
	}

	return info
}

// collectPermissions 收集权限信息
func collectPermissions() PermissionInfo {
	info := PermissionInfo{
		UID:  os.Getuid(),
		EUID: os.Geteuid(),
	}

	// 读取 capabilities
	file, err := os.Open("/proc/self/status")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "CapEff:") {
				info.CapEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
				break
			}
		}
	}

	// 解析 capabilities
	if info.CapEff != "" {
		capVal, err := strconv.ParseUint(info.CapEff, 16, 64)
		if err == nil {
			// CAP_BPF = 39, CAP_SYS_ADMIN = 21
			info.HasBPF = (capVal & (1 << 39)) != 0
			info.HasAdmin = (capVal & (1 << 21)) != 0
		}
	}

	return info
}

// collectBTFInfo 收集 BTF 信息
func collectBTFInfo() BTFInfo {
	info := BTFInfo{
		VmlinuxPath: "/sys/kernel/btf/vmlinux",
	}

	if _, err := os.Stat(info.VmlinuxPath); err == nil {
		info.VmlinuxExists = true
	}

	return info
}

// collectLoadedProgs 收集已加载的 BPF 程序
func collectLoadedProgs() []BPFProgInfo {
	var progs []BPFProgInfo

	// 尝试使用 bpftool
	output, err := exec.Command("bpftool", "prog", "list", "-j").Output()
	if err == nil {
		// 简单解析 JSON 输出中的 id、type、name
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.Contains(line, `"id"`) {
				// 简单提取，实际可用 json 解析
				prog := BPFProgInfo{}
				// 提取 id
				if idx := strings.Index(line, `"id"`); idx >= 0 {
					rest := line[idx:]
					fmt.Sscanf(rest, `"id":%s`, &prog.ID)
					prog.ID = strings.Trim(prog.ID, `",`)
				}
				progs = append(progs, prog)
			}
		}
	}

	// 如果 bpftool 不可用，尝试读取 /proc
	if len(progs) == 0 {
		// /proc/sys/net/core/bpf_prog_id_* 不是标准的
		// 返回空列表，在输出中说明
	}

	return progs
}

// collectInterfaces 收集网卡信息
func collectInterfaces() []NetInterface {
	var interfaces []NetInterface

	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		// 跳过 loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		ni := NetInterface{
			Name: iface.Name,
		}

		if iface.Flags&net.FlagUp != 0 {
			ni.Status = "UP"
		} else {
			ni.Status = "DOWN"
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				ni.Addrs = append(ni.Addrs, addr.String())
			}
		}

		interfaces = append(interfaces, ni)
	}

	return interfaces
}

// outputToStderr 输出简要信息到 stderr
func outputToStderr(report *DiagReport) {
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "══════════════════════════════════════════════════════════")
	fmt.Fprintln(os.Stderr, "  eBPF 诊断报告")
	fmt.Fprintln(os.Stderr, "══════════════════════════════════════════════════════════")
	fmt.Fprintf(os.Stderr, "错误: %s\n\n", report.Error)

	// 内核
	kernelShort := report.Kernel.Version
	if len(kernelShort) > 50 {
		parts := strings.Fields(kernelShort)
		if len(parts) >= 3 {
			kernelShort = parts[2]
		}
	}
	fmt.Fprintf(os.Stderr, "[内核] %s (%s)\n", kernelShort, report.Kernel.Arch)

	// BPF 配置
	bpfStatus := ""
	switch report.BPFConfig.UnprivilegedBPFDisabled {
	case 0:
		bpfStatus = "unprivileged_bpf_disabled=0 ✓"
	case 1:
		bpfStatus = "unprivileged_bpf_disabled=1 (仅 root)"
	case 2:
		bpfStatus = "unprivileged_bpf_disabled=2 ⚠️  (完全禁用，建议设为 0 或 1)"
	default:
		bpfStatus = fmt.Sprintf("unprivileged_bpf_disabled=%d", report.BPFConfig.UnprivilegedBPFDisabled)
	}
	fmt.Fprintf(os.Stderr, "[BPF]  %s\n", bpfStatus)

	// LSM
	fmt.Fprintf(os.Stderr, "[LSM]  %s\n", report.Security.LSM)

	// Lockdown
	if report.Security.Lockdown != "" && report.Security.Lockdown != "未启用" {
		fmt.Fprintf(os.Stderr, "[锁定] %s\n", report.Security.Lockdown)
	}

	// 权限
	capBPF := "✗"
	if report.Permissions.HasBPF {
		capBPF = "✓"
	}
	capAdmin := "✗"
	if report.Permissions.HasAdmin {
		capAdmin = "✓"
	}
	fmt.Fprintf(os.Stderr, "[权限] UID=%d, CAP_BPF=%s, CAP_SYS_ADMIN=%s\n",
		report.Permissions.EUID, capBPF, capAdmin)

	// BTF
	btfStatus := "✗"
	if report.BTF.VmlinuxExists {
		btfStatus = "✓"
	}
	fmt.Fprintf(os.Stderr, "[BTF]  %s %s\n", report.BTF.VmlinuxPath, btfStatus)

	fmt.Fprintln(os.Stderr)
}

// saveToFile 保存完整报告到文件
func saveToFile(report *DiagReport) string {
	timestamp := report.Timestamp.Format("20060102-150405")
	filename := fmt.Sprintf("sninsight-diag-%s.txt", timestamp)
	filePath := filepath.Join(os.TempDir(), filename)

	var sb strings.Builder

	sb.WriteString("# Sninsight eBPF 诊断报告\n")
	sb.WriteString(fmt.Sprintf("生成时间: %s\n\n", report.Timestamp.Format("2006-01-02 15:04:05")))

	// 原始错误
	sb.WriteString("## 原始错误\n")
	sb.WriteString(report.Error)
	sb.WriteString("\n\n")

	// 内核信息
	sb.WriteString("## 内核信息\n")
	sb.WriteString(fmt.Sprintf("版本: %s\n", report.Kernel.Version))
	sb.WriteString(fmt.Sprintf("架构: %s\n\n", report.Kernel.Arch))

	// BPF 配置
	sb.WriteString("## BPF 配置\n")
	sb.WriteString(fmt.Sprintf("unprivileged_bpf_disabled: %d\n", report.BPFConfig.UnprivilegedBPFDisabled))
	sb.WriteString(fmt.Sprintf("bpf_jit_enable: %d\n\n", report.BPFConfig.BPFJITEnable))

	// 安全模块
	sb.WriteString("## 安全模块\n")
	sb.WriteString(fmt.Sprintf("LSM: %s\n", report.Security.LSM))
	sb.WriteString(fmt.Sprintf("Lockdown: %s\n", report.Security.Lockdown))
	sb.WriteString(fmt.Sprintf("SELinux: %s\n", report.Security.SELinux))
	sb.WriteString(fmt.Sprintf("AppArmor: %s\n\n", report.Security.AppArmor))

	// 权限
	sb.WriteString("## 权限\n")
	sb.WriteString(fmt.Sprintf("UID: %d\n", report.Permissions.UID))
	sb.WriteString(fmt.Sprintf("EUID: %d\n", report.Permissions.EUID))
	sb.WriteString(fmt.Sprintf("CapEff: %s\n", report.Permissions.CapEff))
	sb.WriteString(fmt.Sprintf("CAP_BPF: %v\n", report.Permissions.HasBPF))
	sb.WriteString(fmt.Sprintf("CAP_SYS_ADMIN: %v\n\n", report.Permissions.HasAdmin))

	// BTF
	sb.WriteString("## BTF\n")
	sb.WriteString(fmt.Sprintf("vmlinux 路径: %s\n", report.BTF.VmlinuxPath))
	sb.WriteString(fmt.Sprintf("vmlinux 存在: %v\n\n", report.BTF.VmlinuxExists))

	// 已加载 BPF 程序
	sb.WriteString("## 已加载 BPF 程序\n")
	if len(report.LoadedProgs) > 0 {
		for _, prog := range report.LoadedProgs {
			sb.WriteString(fmt.Sprintf("- ID: %s, Type: %s, Name: %s\n", prog.ID, prog.Type, prog.Name))
		}
	} else {
		sb.WriteString("(无法获取或为空，可能需要 bpftool)\n")
	}
	sb.WriteString("\n")

	// 网卡
	sb.WriteString("## 网卡\n")
	for _, iface := range report.Interfaces {
		addrs := strings.Join(iface.Addrs, ", ")
		if addrs == "" {
			addrs = "无地址"
		}
		sb.WriteString(fmt.Sprintf("- %s: %s, %s\n", iface.Name, iface.Status, addrs))
	}

	// 写入文件
	err := os.WriteFile(filePath, []byte(sb.String()), 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "警告: 无法保存诊断报告到文件: %v\n", err)
		return ""
	}

	fmt.Fprintf(os.Stderr, "完整报告已保存: %s\n", filePath)
	fmt.Fprintln(os.Stderr, "══════════════════════════════════════════════════════════")

	return filePath
}
