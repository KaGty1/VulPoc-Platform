package parser

import (
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type HTMLParser struct{}

func (HTMLParser) Name() string  { return "HTMLParser" }
func (HTMLParser) Priority() int { return 75 }
func (HTMLParser) Match(file FileCandidate) bool {
	return file.FileType == "html"
}

func (HTMLParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	raw := string(file.Bytes)
	text := utils.HTMLToText(raw)
	title := utils.Summarize(text, 80)
	if title == "" {
		title = strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	}
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(text),
		Description: utils.Summarize(text, 300),
		Summary:     utils.Summarize(text, 220),
		Content:     raw,
		Tags:        utils.DeriveTags(text, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(text),
		References:  utils.ExtractLinks(raw),
		Author:      utils.ExtractAuthor(text),
		PublishedAt: utils.ExtractDate(text),
		UpdatedAt:   utils.ExtractDate(text),
		SourceType:  "article",
	}, nil
}
