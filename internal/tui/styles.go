package tui

import "github.com/charmbracelet/lipgloss"

var (
	// 颜色定义
	primaryColor   = lipgloss.Color("39")  // 青色
	secondaryColor = lipgloss.Color("243") // 灰色
	successColor   = lipgloss.Color("42")  // 绿色
	warningColor   = lipgloss.Color("214") // 橙色

	// 标题样式
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginBottom(1)

	// Header 样式
	headerStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(secondaryColor)

	// 表格头样式
	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(primaryColor).
				Padding(0, 1)

	// 表格行样式
	tableRowStyle = lipgloss.NewStyle().
			Padding(0, 1)

	// 选中行样式
	selectedRowStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(lipgloss.Color("255")).
				Padding(0, 1)

	// Footer 样式
	footerStyle = lipgloss.NewStyle().
			Foreground(secondaryColor).
			MarginTop(1)

	// 速率样式 (入站)
	inRateStyle = lipgloss.NewStyle().
			Foreground(successColor)

	// 速率样式 (出站)
	outRateStyle = lipgloss.NewStyle().
			Foreground(warningColor)
)
