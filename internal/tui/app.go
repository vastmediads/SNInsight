package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickproject/sninsight/internal/aggregator"
)

// Config TUI 配置
type Config struct {
	SupportsDirection bool
	Hostname          string
	KernelVersion     string
	Interfaces        []string
}

// Model TUI 模型
type Model struct {
	config      Config
	entries     []aggregator.TrafficEntry
	sortMode    aggregator.SortMode
	paused      bool
	filterInput textinput.Model
	filtering   bool
	filterText  string
	selected    int
	width       int
	height      int
	startTime   time.Time
	totalIn     uint64
	totalOut    uint64
	showHelp    bool
	entriesChan <-chan []aggregator.TrafficEntry
}

// 消息类型
type entriesMsg []aggregator.TrafficEntry

// New 创建 TUI 模型
func New(cfg Config, entriesChan <-chan []aggregator.TrafficEntry) Model {
	ti := textinput.New()
	ti.Placeholder = "输入过滤关键词..."
	ti.CharLimit = 50

	return Model{
		config:      cfg,
		sortMode:    aggregator.SortByInRate,
		filterInput: ti,
		startTime:   time.Now(),
		entriesChan: entriesChan,
		width:       80,
		height:      24,
	}
}

// Init 初始化
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		waitForEntries(m.entriesChan),
	)
}

func waitForEntries(ch <-chan []aggregator.TrafficEntry) tea.Cmd {
	return func() tea.Msg {
		entries, ok := <-ch
		if !ok {
			return nil
		}
		return entriesMsg(entries)
	}
}

// Update 更新状态
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.filtering {
			return m.handleFilterInput(msg)
		}
		return m.handleKeyPress(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case entriesMsg:
		if !m.paused {
			m.entries = []aggregator.TrafficEntry(msg)
			m.applyFilter()
			aggregator.Sort(m.entries, m.sortMode)
			m.updateTotals()
		}
		cmds = append(cmds, waitForEntries(m.entriesChan))
		return m, tea.Batch(cmds...)
	}

	return m, nil
}

func (m Model) handleKeyPress(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "s":
		m.sortMode = (m.sortMode + 1) % 4
		aggregator.Sort(m.entries, m.sortMode)
	case "p":
		m.paused = !m.paused
	case "/":
		m.filtering = true
		m.filterInput.Focus()
		return m, textinput.Blink
	case "?":
		m.showHelp = !m.showHelp
	case "up", "k":
		if m.selected > 0 {
			m.selected--
		}
	case "down", "j":
		if m.selected < len(m.entries)-1 {
			m.selected++
		}
	case "home":
		m.selected = 0
	case "end":
		if len(m.entries) > 0 {
			m.selected = len(m.entries) - 1
		}
	}
	return m, nil
}

func (m Model) handleFilterInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filterText = m.filterInput.Value()
		m.filtering = false
		m.filterInput.Blur()
		m.applyFilter()
	case "esc":
		m.filtering = false
		m.filterInput.Blur()
		m.filterInput.SetValue(m.filterText)
	default:
		var cmd tea.Cmd
		m.filterInput, cmd = m.filterInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *Model) applyFilter() {
	if m.filterText == "" {
		return
	}
	filter := strings.ToLower(m.filterText)
	filtered := make([]aggregator.TrafficEntry, 0)
	for _, e := range m.entries {
		if strings.Contains(strings.ToLower(e.DisplayName), filter) {
			filtered = append(filtered, e)
		}
	}
	m.entries = filtered
}

func (m *Model) updateTotals() {
	m.totalIn = 0
	m.totalOut = 0
	for _, e := range m.entries {
		m.totalIn += e.InRate
		m.totalOut += e.OutRate
	}
}

// View 渲染视图
func (m Model) View() string {
	if m.showHelp {
		return m.renderHelp()
	}

	var b strings.Builder

	// Header
	b.WriteString(m.renderHeader())
	b.WriteString("\n")

	// Table
	b.WriteString(m.renderTable())

	// Footer
	b.WriteString(m.renderFooter())

	return b.String()
}

func (m Model) renderHeader() string {
	runtime := time.Since(m.startTime).Round(time.Second)

	line1 := fmt.Sprintf(" Sninsight | Host: %s | Kernel: %s | NICs: %s",
		m.config.Hostname,
		m.config.KernelVersion,
		strings.Join(m.config.Interfaces, ", "))

	var line2 string
	if m.config.SupportsDirection {
		line2 = fmt.Sprintf(" Total: down %s  up %s | Connections: %d | Runtime: %s",
			inRateStyle.Render(FormatRate(m.totalIn)),
			outRateStyle.Render(FormatRate(m.totalOut)),
			len(m.entries),
			runtime)
	} else {
		line2 = fmt.Sprintf(" Total: %s | Connections: %d | Runtime: %s",
			FormatRate(m.totalIn+m.totalOut),
			len(m.entries),
			runtime)
	}

	if m.paused {
		line2 += " [PAUSED]"
	}

	return titleStyle.Render(line1) + "\n" + headerStyle.Render(line2)
}

func (m Model) renderTable() string {
	var b strings.Builder

	// 表头
	var header string
	if m.config.SupportsDirection {
		header = fmt.Sprintf(" %-30s %5s %12s %12s %10s %6s",
			"Domain/IP", "Proto", "In Rate", "Out Rate", "Total", "Conns")
	} else {
		header = fmt.Sprintf(" %-30s %5s %12s %10s %6s",
			"Domain/IP", "Proto", "Rate", "Total", "Conns")
	}
	b.WriteString(tableHeaderStyle.Render(header))
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", m.width))
	b.WriteString("\n")

	// 计算可显示行数
	maxRows := m.height - 8
	if maxRows < 1 {
		maxRows = 10
	}

	// 显示条目
	for i, entry := range m.entries {
		if i >= maxRows {
			break
		}

		name := TruncateString(entry.DisplayName, 30)
		var row string
		if m.config.SupportsDirection {
			row = fmt.Sprintf(" %-30s %5s %12s %12s %10s %6d",
				name,
				entry.Protocol,
				inRateStyle.Render(FormatRate(entry.InRate)),
				outRateStyle.Render(FormatRate(entry.OutRate)),
				FormatBytes(entry.Total()),
				entry.ConnCount)
		} else {
			row = fmt.Sprintf(" %-30s %5s %12s %10s %6d",
				name,
				entry.Protocol,
				FormatRate(entry.InRate+entry.OutRate),
				FormatBytes(entry.Total()),
				entry.ConnCount)
		}

		if i == m.selected {
			b.WriteString(selectedRowStyle.Render(row))
		} else {
			b.WriteString(tableRowStyle.Render(row))
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderFooter() string {
	sortNames := []string{"In Rate", "Out Rate", "Total", "Conns"}
	sortName := sortNames[m.sortMode]

	var footer string
	if m.filtering {
		footer = " Filter: " + m.filterInput.View()
	} else {
		footer = fmt.Sprintf(" [q]uit  [s]ort: %s  [p]ause  [/]filter  [?]help", sortName)
		if m.filterText != "" {
			footer += fmt.Sprintf("  Filter: %s", m.filterText)
		}
	}

	return footerStyle.Render(footer)
}

func (m Model) renderHelp() string {
	help := `
 Sninsight 快捷键帮助

 导航:
   up/k     向上移动
   down/j   向下移动
   Home     跳到顶部
   End      跳到底部

 操作:
   s        切换排序模式 (In Rate -> Out Rate -> Total -> Conns)
   p        暂停/恢复刷新
   /        输入过滤关键词
   ?        显示/隐藏帮助

 退出:
   q        退出程序
   Ctrl+C   退出程序

 按任意键返回...
`
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(help)
}

// Run 运行 TUI
func Run(cfg Config, entriesChan <-chan []aggregator.TrafficEntry) error {
	p := tea.NewProgram(
		New(cfg, entriesChan),
		tea.WithAltScreen(),
	)

	_, err := p.Run()
	return err
}
