package parser

import (
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type GenericTextParser struct{}

func (GenericTextParser) Name() string  { return "GenericTextParser" }
func (GenericTextParser) Priority() int { return 10 }
func (GenericTextParser) Match(file FileCandidate) bool {
	return file.FileType == "text" || file.FileType == "xml" || file.FileType == "csv"
}

func (GenericTextParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	content := string(file.Bytes)
	title := strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(title + "\n" + content),
		Description: utils.Summarize(content, 300),
		Summary:     utils.Summarize(content, 220),
		Content:     content,
		Tags:        utils.DeriveTags(title+"\n"+content, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(content),
		References:  utils.ExtractLinks(content),
		PublishedAt: utils.ExtractDate(content),
		UpdatedAt:   utils.ExtractDate(content),
		SourceType:  "article",
	}, nil
}
