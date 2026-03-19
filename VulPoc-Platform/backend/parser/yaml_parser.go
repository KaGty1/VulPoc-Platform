package parser

import (
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type YAMLParser struct{}

func (YAMLParser) Name() string  { return "YAMLParser" }
func (YAMLParser) Priority() int { return 85 }
func (YAMLParser) Match(file FileCandidate) bool {
	return file.FileType == "yaml"
}

func (YAMLParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	var payload any
	if err := yaml.Unmarshal(file.Bytes, &payload); err != nil {
		return model.Entry{}, err
	}
	pretty := utils.PrettyJSON(payload)
	title := findStructuredString(payload, "title", "name", "id")
	if title == "" {
		title = strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	}
	description := findStructuredString(payload, "description", "summary", "detail", "content")
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(title + "\n" + pretty),
		Description: choose(description, utils.Summarize(pretty, 300)),
		Summary:     utils.Summarize(choose(description, pretty), 220),
		Content:     pretty,
		POC:         findStructuredString(payload, "poc", "payload", "request", "exploit"),
		Exp:         findStructuredString(payload, "exp", "script"),
		Tags:        utils.DeriveTags(title+"\n"+pretty, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(pretty),
		References:  utils.ExtractLinks(pretty),
		Author:      findStructuredString(payload, "author", "creator"),
		PublishedAt: choose(findStructuredString(payload, "published_at", "created_at", "date"), utils.ExtractDate(pretty)),
		UpdatedAt:   findStructuredString(payload, "updated_at", "modified_at"),
		SourceType:  "yaml",
	}, nil
}
