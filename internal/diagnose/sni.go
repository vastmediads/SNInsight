//go:build linux

package diagnose

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/nickproject/sninsight/internal/parser"
	"github.com/vishvananda/netlink"
)

// SNIDiagnoseConfig SNI 诊断配置
type SNIDiagnoseConfig struct {
	TestDomain string        // 测试域名，默认 cloudflare.com
	Timeout    time.Duration // 超时时间
	Interface  string        // 指定网卡（可选）
}

// DefaultSNIConfig 默认 SNI 诊断配置
func DefaultSNIConfig() SNIDiagnoseConfig {
	return SNIDiagnoseConfig{
		TestDomain: "cloudflare.com",
		Timeout:    10 * time.Second,
	}
}

// SNIDiagnose SNI 诊断器
type SNIDiagnose struct {
	cfg    SNIDiagnoseConfig
	report *DiagnoseReport
}

// NewSNIDiagnose 创建 SNI 诊断器
func NewSNIDiagnose(cfg SNIDiagnoseConfig) *SNIDiagnose {
	return &SNIDiagnose{
		cfg:    cfg,
		report: NewDiagnoseReport("sni"),
	}
}

// tlsEventData TLS 事件数据
type tlsEventData struct {
	TimestampNs uint64
	SrcIP       uint32
	DstIP       uint32
	SrcPort     uint16
	DstPort     uint16
	Proto       uint8
	Direction   uint8
	PayloadLen  uint16
	Payload     [256]byte
}

// Run 运行 SNI 诊断
func (d *SNIDiagnose) Run() *DiagnoseReport {
	d.report.System = CollectSystemInfo()

	// 1. 检查权限
	d.checkPermissions()

	// 2. 检查 eBPF 程序是否可以加载（简化检查）
	if !d.checkEBPFAvailable() {
		d.report.SetSummary("eBPF 环境检查失败，无法进行 SNI 诊断")
		return d.report
	}

	// 3. 尝试加载 eBPF 并运行测试
	d.runCaptureTest()

	// 生成摘要
	d.generateSummary()

	return d.report
}

// checkPermissions 检查权限
func (d *SNIDiagnose) checkPermissions() {
	perms := collectPermissions()

	if perms.EUID == 0 {
		d.report.AddCheck("permissions", StatusPass, "以 root 权限运行")
	} else if perms.HasBPF && perms.HasAdmin {
		d.report.AddCheck("permissions", StatusPass,
			fmt.Sprintf("具有必要的 capabilities (UID=%d)", perms.EUID))
	} else {
		d.report.AddCheck("permissions", StatusFail,
			fmt.Sprintf("权限不足: UID=%d, CAP_BPF=%v, CAP_SYS_ADMIN=%v",
				perms.EUID, perms.HasBPF, perms.HasAdmin))
	}
}

// checkEBPFAvailable 检查 eBPF 是否可用
func (d *SNIDiagnose) checkEBPFAvailable() bool {
	btf := collectBTFInfo()
	if !btf.VmlinuxExists {
		d.report.AddCheck("btf", StatusFail, "BTF vmlinux 不存在")
		return false
	}
	d.report.AddCheck("btf", StatusPass, "BTF vmlinux 存在")

	// 检查网卡
	ifaces := collectInterfaces()
	upCount := 0
	for _, iface := range ifaces {
		if iface.Status == "UP" {
			upCount++
		}
	}
	if upCount == 0 {
		d.report.AddCheck("interfaces", StatusFail, "没有可用的网卡")
		return false
	}
	d.report.AddCheck("interfaces", StatusPass, fmt.Sprintf("发现 %d 个可用网卡", upCount))

	return true
}

// runCaptureTest 运行抓包测试
func (d *SNIDiagnose) runCaptureTest() {
	// 加载 eBPF 程序
	spec, err := loadTrafficSpec()
	if err != nil {
		d.report.AddCheckWithError("ebpf_spec", StatusFail, "加载 eBPF spec 失败", err)
		return
	}

	var objs trafficObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		d.report.AddCheckWithError("ebpf_load", StatusFail, "加载 eBPF 程序失败", err)
		return
	}
	defer objs.Close()

	d.report.AddCheck("ebpf_load", StatusPass, "eBPF 程序加载成功")

	// 获取网卡并附加 TC
	iface := d.cfg.Interface
	if iface == "" {
		// 自动选择第一个非 loopback 的 UP 网卡
		ifaces, _ := net.Interfaces()
		for _, i := range ifaces {
			if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
				iface = i.Name
				break
			}
		}
	}

	if iface == "" {
		d.report.AddCheck("tc_attach", StatusFail, "没有找到可用的网卡")
		return
	}

	// 附加 TC
	link, err := netlink.LinkByName(iface)
	if err != nil {
		d.report.AddCheckWithError("tc_attach", StatusFail, "找不到网卡: "+iface, err)
		return
	}

	// 添加 clsact qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	netlink.QdiscAdd(qdisc) // 忽略已存在错误
	defer netlink.QdiscDel(qdisc)

	// 附加 egress filter
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Priority:  1,
			Protocol:  0x0003,
		},
		Fd:           objs.TcEgress.FD(),
		Name:         "sninsight_diag_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		d.report.AddCheckWithError("tc_attach", StatusFail, "附加 TC filter 失败", err)
		return
	}
	defer netlink.FilterDel(filter)

	d.report.AddCheck("tc_attach", StatusPass, fmt.Sprintf("TC 程序已附加到 %s", iface))

	// 创建 ring buffer reader
	reader, err := ringbuf.NewReader(objs.TlsEvents)
	if err != nil {
		d.report.AddCheckWithError("ringbuf", StatusFail, "创建 ring buffer reader 失败", err)
		return
	}
	defer reader.Close()

	// 启动事件收集
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.Timeout)
	defer cancel()

	var wg sync.WaitGroup
	var capturedEvents []tlsEventData
	var eventMu sync.Mutex
	var sniFound string
	var sniParseErr error
	var sniParsePayloadLen uint16
	var sniParseRawLen int

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				continue
			}

			if len(record.RawSample) < 24 {
				continue
			}

			evt := parseTLSEvent(record.RawSample)
			if evt != nil {
				eventMu.Lock()
				capturedEvents = append(capturedEvents, *evt)

				// 尝试解析 SNI，记录详细错误
				if evt.PayloadLen > 0 {
					payload := evt.Payload[:evt.PayloadLen]
					sni, err := parser.ExtractSNI(payload)
					if err == nil && sni != "" {
						sniFound = sni
					} else if sniParseErr == nil && err != nil {
						// 记录第一个解析错误
						sniParseErr = err
						sniParsePayloadLen = evt.PayloadLen
						sniParseRawLen = len(record.RawSample)
					}
				}
				eventMu.Unlock()
			}
		}
	}()

	// 等待一小段时间让 eBPF 完全就绪
	time.Sleep(500 * time.Millisecond)

	// 发起 HTTPS 请求
	testURL := fmt.Sprintf("https://%s/", d.cfg.TestDomain)
	httpErr := d.makeHTTPSRequest(testURL)

	if httpErr != nil {
		d.report.AddCheckWithError("https_request", StatusWarning,
			fmt.Sprintf("HTTPS 请求 %s 失败", d.cfg.TestDomain), httpErr)
	} else {
		d.report.AddCheck("https_request", StatusPass,
			fmt.Sprintf("HTTPS 请求 %s 成功", d.cfg.TestDomain))
	}

	// 等待事件收集
	time.Sleep(2 * time.Second)
	cancel()
	reader.Close()
	wg.Wait()

	// 分析结果
	eventMu.Lock()
	eventCount := len(capturedEvents)
	foundSNI := sniFound
	parseErr := sniParseErr
	parsePayloadLen := sniParsePayloadLen
	parseRawLen := sniParseRawLen
	eventMu.Unlock()

	// 检查 TLS 事件捕获
	if eventCount > 0 {
		d.report.AddCheckWithDetails("tls_capture", StatusPass,
			fmt.Sprintf("捕获到 %d 个 TLS 事件", eventCount),
			map[string]any{"event_count": eventCount})
	} else {
		d.report.AddCheck("tls_capture", StatusFail,
			"未捕获到任何 TLS 事件")
	}

	// 检查 SNI 解析
	if foundSNI != "" {
		d.report.AddCheckWithDetails("sni_parse", StatusPass,
			fmt.Sprintf("成功解析 SNI: %s", foundSNI),
			map[string]any{"sni": foundSNI})
	} else if eventCount > 0 {
		errMsg := "捕获到 TLS 事件但无法解析 SNI"
		details := map[string]any{}
		if parseErr != nil {
			errMsg = fmt.Sprintf("SNI 解析失败: %v", parseErr)
			details["error"] = parseErr.Error()
			details["payload_len"] = parsePayloadLen
			details["raw_sample_len"] = parseRawLen
		}
		d.report.AddCheckWithDetails("sni_parse", StatusFail, errMsg, details)
	} else {
		d.report.AddCheck("sni_parse", StatusSkipped, "无 TLS 事件，跳过 SNI 解析检查")
	}
}

// parseTLSEvent 解析 TLS 事件
func parseTLSEvent(data []byte) *tlsEventData {
	if len(data) < 24 {
		return nil
	}

	evt := &tlsEventData{}
	evt.TimestampNs = binary.LittleEndian.Uint64(data[0:8])
	evt.SrcIP = binary.LittleEndian.Uint32(data[8:12])
	evt.DstIP = binary.LittleEndian.Uint32(data[12:16])
	evt.SrcPort = binary.LittleEndian.Uint16(data[16:18])
	evt.DstPort = binary.LittleEndian.Uint16(data[18:20])
	evt.Proto = data[20]
	evt.Direction = data[21]
	evt.PayloadLen = binary.LittleEndian.Uint16(data[22:24])

	if evt.PayloadLen > 0 && len(data) >= 24+int(evt.PayloadLen) {
		copy(evt.Payload[:], data[24:24+evt.PayloadLen])
	}

	return evt
}

// makeHTTPSRequest 发起 HTTPS 请求
func (d *SNIDiagnose) makeHTTPSRequest(url string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DialContext: (&net.Dialer{
				Timeout: 3 * time.Second,
			}).DialContext,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// generateSummary 生成摘要
func (d *SNIDiagnose) generateSummary() {
	passCount := 0
	failCount := 0
	warnCount := 0

	for _, check := range d.report.Checks {
		switch check.Status {
		case StatusPass:
			passCount++
		case StatusFail:
			failCount++
		case StatusWarning:
			warnCount++
		}
	}

	if failCount == 0 && warnCount == 0 {
		d.report.SetSummary(fmt.Sprintf("所有 %d 项检查通过，SNI 捕获功能正常", passCount))
	} else if failCount == 0 {
		d.report.SetSummary(fmt.Sprintf("%d 项通过，%d 项警告，SNI 捕获基本正常", passCount, warnCount))
	} else {
		var failedChecks []string
		for _, check := range d.report.Checks {
			if check.Status == StatusFail {
				failedChecks = append(failedChecks, check.Name)
			}
		}
		d.report.SetSummary(fmt.Sprintf("SNI 捕获存在问题：%d 项失败，%d 项警告。失败项: %v",
			failCount, warnCount, failedChecks))
	}
}

// loadTrafficSpec 加载 eBPF spec（复用 capture 包生成的代码）
func loadTrafficSpec() (*ebpf.CollectionSpec, error) {
	return loadTraffic()
}

// RunSNIDiagnose 便捷函数：运行 SNI 诊断
func RunSNIDiagnose(testDomain string) *DiagnoseReport {
	cfg := DefaultSNIConfig()
	if testDomain != "" {
		cfg.TestDomain = testDomain
	}

	diag := NewSNIDiagnose(cfg)
	return diag.Run()
}
