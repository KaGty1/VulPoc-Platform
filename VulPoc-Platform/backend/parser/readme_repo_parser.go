package parser

import (
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type ReadmeRepoParser struct{}

func (ReadmeRepoParser) Name() string  { return "ReadmeRepoParser" }
func (ReadmeRepoParser) Priority() int { return 110 }
func (ReadmeRepoParser) Match(dir DirCandidate) bool {
	readmeCount := 0
	for _, file := range dir.Files {
		if utils.IsReadme(file.Name) {
			readmeCount++
		}
	}
	return readmeCount > 0 && len(dir.Files) > 1
}

func (ReadmeRepoParser) Parse(ctx Context, dir DirCandidate) (model.Entry, error) {
	primary := pickPrimaryContent(dir.Files)
	script := pickPrimaryScript(dir.Files)
	content := ""
	title := dir.Name
	description := ""
	references := make([]string, 0, 4)
	if primary != nil {
		entry, _, err := NewRegistry().ParseFile(ctx, *primary)
		if err == nil {
			title = choose(entry.Title, title)
			content = choose(entry.Content, string(primary.Bytes))
			description = choose(entry.Description, entry.Summary)
			references = append(references, entry.References...)
		}
	}
	poc := ""
	exp := ""
	if script != nil {
		poc = string(script.Bytes)
		exp = poc
	}

	searchSeed := strings.Join([]string{title, description, content, poc, dir.RelativePath}, "\n")
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(searchSeed),
		Aliases:     utils.ExtractCVEs(searchSeed),
		Description: choose(description, utils.Summarize(searchSeed, 300)),
		Summary:     utils.Summarize(searchSeed, 220),
		Content:     content,
		POC:         poc,
		Exp:         exp,
		Tags:        utils.DeriveTags(searchSeed, dir.RelativePath),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(searchSeed),
		References:  append(references, utils.ExtractLinks(searchSeed)...),
		PublishedAt: utils.ExtractDate(searchSeed),
		UpdatedAt:   utils.ExtractDate(searchSeed),
		SourceType:  "repo",
		Files:       BuildEntryFiles(dir.Files, ctx.MaxInlineFileSize),
	}, nil
}
