package parser

import (
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type MarkdownParser struct{}

func (MarkdownParser) Name() string  { return "MarkdownParser" }
func (MarkdownParser) Priority() int { return 100 }
func (MarkdownParser) Match(file FileCandidate) bool {
	return file.FileType == "markdown" || file.FileType == "readme"
}

func (MarkdownParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	content := string(file.Bytes)
	title := utils.FirstMarkdownHeading(content)
	if title == "" {
		title = strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	}
	bodyContent := utils.RemoveFirstMarkdownHeading(content)
	descriptionSection := utils.ExtractMarkdownSection(bodyContent, "漏洞描述", "描述", "Description", "Summary")
	if descriptionSection == "" {
		descriptionSection = bodyContent
	}
	descriptionText := utils.MarkdownToPlainText(descriptionSection)
	summarySource := descriptionText
	if summarySource == "" {
		summarySource = utils.MarkdownToPlainText(bodyContent)
	}

	codeBlocks := utils.ExtractCodeBlocks(content)
	poc := ""
	exp := ""
	if len(codeBlocks) > 0 {
		poc = codeBlocks[0]
	}
	if len(codeBlocks) > 1 {
		exp = codeBlocks[1]
	}

	description := utils.Summarize(descriptionText, 380)
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(title + "\n" + content),
		Aliases:     utils.ExtractCVEs(content),
		Description: description,
		Summary:     utils.Summarize(summarySource, 220),
		Content:     content,
		POC:         poc,
		Exp:         exp,
		Tags:        utils.DeriveTags(title+"\n"+content, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(content),
		References:  utils.ExtractLinks(content),
		Author:      utils.ExtractAuthor(descriptionText + "\n" + content),
		PublishedAt: utils.ExtractDate(descriptionText + "\n" + content),
		UpdatedAt:   utils.ExtractDate(descriptionText + "\n" + content),
		SourceType:  sourceTypeForFile(file),
	}, nil
}
