package filter

import (
	"path/filepath"
	"strings"
)

// Filter 域名过滤器
type Filter struct {
	includePatterns []string
	excludePatterns []string
}

// New 创建过滤器
func New(include, exclude []string) *Filter {
	return &Filter{
		includePatterns: normalizePatterns(include),
		excludePatterns: normalizePatterns(exclude),
	}
}

// normalizePatterns 规范化通配符模式
func normalizePatterns(patterns []string) []string {
	result := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// Match 判断域名是否应该显示
// 返回 true 表示应该显示，false 表示应该过滤掉
func (f *Filter) Match(domain string) bool {
	domain = strings.ToLower(domain)

	// 如果在排除列表中，直接过滤
	for _, pattern := range f.excludePatterns {
		if matchPattern(pattern, domain) {
			return false
		}
	}

	// 如果没有包含列表，默认显示
	if len(f.includePatterns) == 0 {
		return true
	}

	// 检查是否在包含列表中
	for _, pattern := range f.includePatterns {
		if matchPattern(pattern, domain) {
			return true
		}
	}

	return false
}

// matchPattern 使用通配符匹配域名
// 支持 * 和 ? 通配符
// 例如: *.google.com 匹配 www.google.com, mail.google.com
func matchPattern(pattern, domain string) bool {
	// 处理 *.example.com 格式
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		return strings.HasSuffix(domain, suffix) || domain == pattern[2:]
	}

	// 使用 filepath.Match 进行通配符匹配
	matched, err := filepath.Match(pattern, domain)
	if err != nil {
		return false
	}
	return matched
}

// IsEmpty 检查过滤器是否为空（无任何规则）
func (f *Filter) IsEmpty() bool {
	return len(f.includePatterns) == 0 && len(f.excludePatterns) == 0
}
