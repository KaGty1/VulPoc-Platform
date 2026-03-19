package parser

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type JSONParser struct{}

func (JSONParser) Name() string  { return "JSONParser" }
func (JSONParser) Priority() int { return 90 }
func (JSONParser) Match(file FileCandidate) bool {
	return file.FileType == "json"
}

func (JSONParser) Parse(_ Context, file FileCandidate) (model.Entry, error) {
	var payload any
	if err := json.Unmarshal(file.Bytes, &payload); err != nil {
		return model.Entry{}, err
	}
	pretty := utils.PrettyJSON(payload)
	title := findStructuredString(payload, "title", "name", "vuln", "id")
	if title == "" {
		title = strings.TrimSuffix(filepath.Base(file.Name), filepath.Ext(file.Name))
	}
	description := findStructuredString(payload, "description", "summary", "detail", "content")
	poc := findStructuredString(payload, "poc", "payload", "request", "exploit")
	references := utils.ExtractLinks(pretty)
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(pretty + "\n" + title),
		Description: choose(description, utils.Summarize(pretty, 300)),
		Summary:     utils.Summarize(choose(description, pretty), 220),
		Content:     pretty,
		POC:         poc,
		Exp:         findStructuredString(payload, "exp", "exploit", "script"),
		Tags:        utils.DeriveTags(title+"\n"+pretty, file.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(pretty),
		References:  references,
		Author:      findStructuredString(payload, "author", "creator"),
		PublishedAt: choose(findStructuredString(payload, "published_at", "created_at", "date"), utils.ExtractDate(pretty)),
		UpdatedAt:   choose(findStructuredString(payload, "updated_at", "modified_at"), utils.ExtractDate(pretty)),
		SourceType:  "json",
	}, nil
}

func findStructuredString(payload any, keys ...string) string {
	object, ok := payload.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range keys {
		for currentKey, value := range object {
			if !strings.EqualFold(currentKey, key) {
				continue
			}
			switch typed := value.(type) {
			case string:
				return strings.TrimSpace(typed)
			default:
				if rendered := utils.PrettyJSON(typed); rendered != "" {
					return rendered
				}
			}
		}
	}
	return ""
}
