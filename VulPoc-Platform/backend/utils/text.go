package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"golang.org/x/net/html"
)

var (
	cvePattern     = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
	urlPattern     = regexp.MustCompile(`https?://[^\s\])">]+`)
	versionPattern = regexp.MustCompile(`(?i)\b(v(?:ersion)?\s*[:=]?\s*[0-9][0-9A-Za-z.\-_/]*)\b`)
	mdImagePattern = regexp.MustCompile(`!\[[^\]]*]\([^)]+\)`)
	mdLinkPattern  = regexp.MustCompile(`\[([^\]]+)]\([^)]+\)`)
	mdFencePattern = regexp.MustCompile("(?s)```.*?```")
	mdInlineCode   = regexp.MustCompile("`([^`]*)`")
	mdListPrefix   = regexp.MustCompile(`^\s*[-*+]\s+`)
	datePatterns   = []*regexp.Regexp{
		regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`),
		regexp.MustCompile(`\b\d{4}/\d{2}/\d{2}\b`),
		regexp.MustCompile(`\b\d{4}\.\d{2}\.\d{2}\b`),
	}
)

var supportedExtensions = map[string]string{
	".md":       "markdown",
	".markdown": "markdown",
	".txt":      "text",
	".html":     "html",
	".htm":      "html",
	".json":     "json",
	".yaml":     "yaml",
	".yml":      "yaml",
	".xml":      "xml",
	".csv":      "csv",
	".pdf":      "pdf",
	".py":       "script",
	".sh":       "script",
	".go":       "script",
	".js":       "script",
	".ts":       "script",
	".rb":       "script",
	".ps1":      "script",
	".java":     "script",
	".c":        "script",
	".cpp":      "script",
	".php":      "script",
	".jsp":      "script",
	".asp":      "script",
	".aspx":     "script",
	".sql":      "script",
}

var bundleExtensions = map[string]string{
	".png":  "image",
	".jpg":  "image",
	".jpeg": "image",
	".gif":  "image",
	".webp": "image",
	".svg":  "image",
	".zip":  "archive",
	".rar":  "archive",
	".7z":   "archive",
	".gz":   "archive",
	".tar":  "archive",
}

var scriptLanguages = map[string]string{
	".py":   "python",
	".sh":   "bash",
	".go":   "go",
	".js":   "javascript",
	".ts":   "typescript",
	".rb":   "ruby",
	".ps1":  "powershell",
	".java": "java",
	".c":    "c",
	".cpp":  "cpp",
	".php":  "php",
	".jsp":  "jsp",
	".asp":  "asp",
	".aspx": "aspx",
	".sql":  "sql",
}

func HashID(parts ...string) string {
	sum := md5.Sum([]byte(strings.Join(parts, "::")))
	return hex.EncodeToString(sum[:])
}

func NormalizeWhitespace(input string) string {
	fields := strings.Fields(strings.ReplaceAll(input, "\u00a0", " "))
	return strings.TrimSpace(strings.Join(fields, " "))
}

func Summarize(input string, limit int) string {
	clean := NormalizeWhitespace(input)
	if clean == "" {
		return ""
	}
	runes := []rune(clean)
	if len(runes) <= limit {
		return clean
	}
	return strings.TrimSpace(string(runes[:limit])) + "..."
}

func UniqueStrings(items []string) []string {
	set := make(map[string]string, len(items))
	for _, item := range items {
		normalized := strings.TrimSpace(item)
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if _, exists := set[key]; !exists {
			set[key] = normalized
		}
	}
	result := make([]string, 0, len(set))
	for _, value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func DetectCVE(text string) string {
	matches := ExtractCVEs(text)
	if len(matches) == 0 {
		return ""
	}
	return matches[0]
}

func ExtractCVEs(text string) []string {
	return UniqueStrings(cvePattern.FindAllString(strings.ToUpper(text), -1))
}

func ExtractLinks(text string) []string {
	return UniqueStrings(urlPattern.FindAllString(text, -1))
}

func ExtractVersions(text string) []string {
	matches := versionPattern.FindAllString(text, -1)
	return UniqueStrings(matches)
}

func ExtractDate(text string) string {
	for _, pattern := range datePatterns {
		if match := pattern.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

func ExtractAuthor(text string) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "author:") || strings.HasPrefix(lower, "作者：") || strings.HasPrefix(lower, "作者:") {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
			parts = strings.SplitN(trimmed, "：", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func FirstMarkdownHeading(text string) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			return strings.TrimSpace(strings.TrimLeft(trimmed, "# "))
		}
	}
	return ""
}

func RemoveFirstMarkdownHeading(text string) string {
	lines := strings.Split(text, "\n")
	removed := false
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !removed && strings.HasPrefix(trimmed, "#") {
			removed = true
			continue
		}
		kept = append(kept, line)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func ExtractMarkdownSection(text string, headings ...string) string {
	lines := strings.Split(text, "\n")
	var captured []string
	capturing := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			currentHeading := strings.TrimSpace(strings.TrimLeft(trimmed, "# "))
			if capturing {
				break
			}
			for _, heading := range headings {
				if strings.EqualFold(currentHeading, heading) {
					capturing = true
					break
				}
			}
			continue
		}
		if capturing {
			captured = append(captured, line)
		}
	}
	return strings.TrimSpace(strings.Join(captured, "\n"))
}

func MarkdownToPlainText(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	content := strings.ReplaceAll(text, "\r\n", "\n")
	content = mdFencePattern.ReplaceAllStringFunc(content, func(block string) string {
		lines := strings.Split(block, "\n")
		if len(lines) <= 2 {
			return ""
		}
		return strings.TrimSpace(strings.Join(lines[1:len(lines)-1], "\n"))
	})
	content = mdImagePattern.ReplaceAllString(content, "")
	content = mdLinkPattern.ReplaceAllString(content, "$1")
	content = mdInlineCode.ReplaceAllString(content, "$1")

	lines := strings.Split(content, "\n")
	cleaned := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			trimmed = strings.TrimSpace(strings.TrimLeft(trimmed, "# "))
		}
		trimmed = mdListPrefix.ReplaceAllString(trimmed, "")
		cleaned = append(cleaned, trimmed)
	}
	return NormalizeWhitespace(strings.Join(cleaned, "\n"))
}

func ExtractCodeBlocks(text string) []string {
	lines := strings.Split(text, "\n")
	blocks := make([]string, 0, 2)
	var current []string
	inFence := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if inFence {
				blocks = append(blocks, strings.TrimSpace(strings.Join(current, "\n")))
				current = nil
			}
			inFence = !inFence
			continue
		}
		if inFence {
			current = append(current, line)
		}
	}
	return UniqueStrings(blocks)
}

func DeriveTags(text, path string) []string {
	seed := strings.ToLower(text + " " + strings.ReplaceAll(path, "/", " "))
	keywords := []string{
		"sql", "注入", "rce", "命令执行", "文件读取", "任意文件读取", "文件上传", "权限绕过",
		"鉴权绕过", "xss", "csrf", "xxe", "ssrf", "反序列化", "信息泄露", "默认密码",
		"目录遍历", "代码执行", "未授权", "漏洞",
	}

	tags := make([]string, 0, 8)
	for _, keyword := range keywords {
		if strings.Contains(seed, keyword) {
			tags = append(tags, keyword)
		}
	}

	for _, cve := range ExtractCVEs(seed) {
		tags = append(tags, cve)
	}

	for _, chunk := range strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '_' || r == '-' || unicode.IsSpace(r)
	}) {
		chunk = strings.TrimSpace(chunk)
		if len([]rune(chunk)) < 3 {
			continue
		}
		if strings.EqualFold(chunk, "assets") || strings.EqualFold(chunk, "images") {
			continue
		}
		tags = append(tags, chunk)
	}

	return UniqueStrings(tags)
}

func DeriveProducts(title string) []string {
	clean := strings.TrimSpace(title)
	if clean == "" {
		return nil
	}

	separators := []string{"漏洞", "CVE-", "任意", "SQL", "RCE", "XSS", "XXE", "SSRF", "默认密码"}
	product := clean
	for _, separator := range separators {
		index := strings.Index(strings.ToUpper(product), strings.ToUpper(separator))
		if index > 0 {
			product = strings.TrimSpace(product[:index])
			break
		}
	}
	product = strings.Trim(product, "-_ ")
	if product == "" {
		return nil
	}
	return UniqueStrings([]string{product})
}

func PrettyJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

func HTMLToText(content string) string {
	doc, err := html.Parse(strings.NewReader(content))
	if err != nil {
		return content
	}

	var buffer bytes.Buffer
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.TextNode {
			buffer.WriteString(node.Data)
			buffer.WriteString(" ")
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	return NormalizeWhitespace(buffer.String())
}

func FileTypeFromExt(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	if fileType, ok := supportedExtensions[ext]; ok {
		return fileType
	}
	if fileType, ok := bundleExtensions[ext]; ok {
		return fileType
	}
	if IsReadme(name) {
		return "readme"
	}
	return ""
}

func IsSupportedContentFile(name string) bool {
	if IsReadme(name) {
		return true
	}
	_, ok := supportedExtensions[strings.ToLower(filepath.Ext(name))]
	return ok
}

func IsBundleAsset(name string) bool {
	_, ok := bundleExtensions[strings.ToLower(filepath.Ext(name))]
	return ok
}

func IsTextLike(name string) bool {
	switch FileTypeFromExt(name) {
	case "markdown", "readme", "text", "html", "json", "yaml", "xml", "csv", "script":
		return true
	default:
		return false
	}
}

func IsReadme(name string) bool {
	base := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	return base == "readme"
}

func CategoryFromFileType(fileType string) string {
	switch fileType {
	case "markdown", "html", "text", "json", "yaml", "xml", "csv", "readme", "pdf":
		return "document"
	case "script":
		return "code"
	case "image":
		return "image"
	case "archive":
		return "archive"
	case "document":
		return "attachment"
	default:
		return "other"
	}
}

func LanguageFromName(name string) string {
	if IsReadme(name) {
		return "markdown"
	}
	return scriptLanguages[strings.ToLower(filepath.Ext(name))]
}

func LooksBinary(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	nonPrintable := 0
	for _, b := range data {
		if b < 9 || (b > 13 && b < 32) {
			nonPrintable++
		}
	}
	return len(data) > 0 && nonPrintable*100/len(data) > 10
}
