package parser

import (
	"fmt"
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type PDFParser struct{}

func (PDFParser) Name() string  { return "PDFParser" }
func (PDFParser) Priority() int { return 70 }

func (PDFParser) Match(file FileCandidate) bool {
	return file.FileType == "pdf"
}

func (PDFParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	title := strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	chapter := firstPathSegment(file.RelativePath)
	searchSeed := strings.Join([]string{title, chapter, file.RelativePath}, "\n")
	description := fmt.Sprintf("域渗透指南 PDF 文档，章节：%s。可在详情页中直接在线阅读原始 PDF。", choose(chapter, "未分类"))
	content := strings.TrimSpace(strings.Join([]string{
		fmt.Sprintf("标题：%s", title),
		fmt.Sprintf("章节：%s", choose(chapter, "未分类")),
		fmt.Sprintf("路径：%s", file.RelativePath),
		"格式：PDF",
	}, "\n"))

	tags := append(utils.DeriveTags(searchSeed, file.RelativePath), "域渗透指南")
	if chapter != "" {
		tags = append(tags, chapter)
	}

	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(searchSeed),
		Aliases:     utils.ExtractCVEs(searchSeed),
		Description: description,
		Summary:     utils.Summarize(title+" "+description, 220),
		Content:     content,
		Tags:        utils.UniqueStrings(tags),
		Products:    utils.DeriveProducts(title),
		SourceType:  "guide",
		FileType:    "pdf",
	}, nil
}

func firstPathSegment(relPath string) string {
	parts := strings.Split(filepath.ToSlash(relPath), "/")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}
