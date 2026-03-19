package parser

import (
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type ScriptParser struct{}

func (ScriptParser) Name() string  { return "ScriptParser" }
func (ScriptParser) Priority() int { return 70 }
func (ScriptParser) Match(file FileCandidate) bool {
	return file.FileType == "script"
}

func (ScriptParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	content := string(file.Bytes)
	title := strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(title + "\n" + content),
		Description: utils.Summarize(content, 280),
		Summary:     utils.Summarize(content, 220),
		Content:     content,
		POC:         content,
		Exp:         content,
		Tags:        utils.DeriveTags(title+"\n"+content, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(content),
		References:  utils.ExtractLinks(content),
		SourceType:  "script",
		FileType:    "script",
	}, nil
}
