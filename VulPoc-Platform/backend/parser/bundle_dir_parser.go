package parser

import (
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type BundleDirParser struct{}

func (BundleDirParser) Name() string  { return "BundleDirParser" }
func (BundleDirParser) Priority() int { return 80 }
func (BundleDirParser) Match(dir DirCandidate) bool {
	return hasPrimaryBundleFiles(dir)
}

func (BundleDirParser) Parse(ctx Context, dir DirCandidate) (model.Entry, error) {
	return buildBundleEntry(ctx, dir, "article")
}

func hasPrimaryBundleFiles(dir DirCandidate) bool {
	contentCount := 0
	for _, file := range dir.Files {
		if file.FileType == "markdown" || file.FileType == "readme" || file.FileType == "html" || file.FileType == "text" || file.FileType == "json" || file.FileType == "yaml" || file.FileType == "xml" || file.FileType == "csv" || file.FileType == "script" {
			contentCount++
		}
	}
	if contentCount == 0 || contentCount > 3 {
		return false
	}
	for _, subdir := range dir.Subdirs {
		name := strings.ToLower(subdir)
		if name == "assets" || name == "images" || name == "img" || name == "static" {
			continue
		}
		return false
	}
	return true
}

func buildBundleEntry(ctx Context, dir DirCandidate, fallbackType string) (model.Entry, error) {
	primary := pickPrimaryContent(dir.Files)
	script := pickPrimaryScript(dir.Files)
	title := dir.Name
	description := ""
	content := ""
	poc := ""
	exp := ""
	aliases := make([]string, 0, 4)
	references := make([]string, 0, 8)
	tags := utils.DeriveTags(dir.Name, dir.RelativePath)

	if primary != nil {
		entry, _, err := NewRegistry().ParseFile(ctx, *primary)
		if err == nil {
			title = choose(entry.Title, title)
			description = choose(entry.Description, entry.Summary)
			content = choose(entry.Content, string(primary.Bytes))
			poc = choose(entry.POC, poc)
			exp = choose(entry.Exp, exp)
			aliases = append(aliases, entry.Aliases...)
			references = append(references, entry.References...)
			tags = append(tags, entry.Tags...)
		}
	}

	if script != nil {
		scriptContent := string(script.Bytes)
		if poc == "" {
			poc = scriptContent
		}
		if exp == "" {
			exp = scriptContent
		}
		content = choose(content, scriptContent)
	}

	seed := strings.Join([]string{title, description, content, poc, exp, dir.RelativePath}, "\n")
	return model.Entry{
		Title:       title,
		CVE:         utils.DetectCVE(seed),
		Aliases:     append(aliases, utils.ExtractCVEs(seed)...),
		Description: choose(description, utils.Summarize(seed, 300)),
		Summary:     utils.Summarize(seed, 220),
		Content:     content,
		POC:         poc,
		Exp:         exp,
		Tags:        append(tags, utils.DeriveTags(seed, dir.RelativePath)...),
		Products:    utils.DeriveProducts(title),
		Versions:    utils.ExtractVersions(seed),
		References:  append(references, utils.ExtractLinks(seed)...),
		PublishedAt: utils.ExtractDate(seed),
		UpdatedAt:   utils.ExtractDate(seed),
		SourceType:  fallbackType,
		Files:       BuildEntryFiles(dir.Files, ctx.MaxInlineFileSize),
	}, nil
}

func sourceTypeForFile(file FileCandidate) string {
	switch file.FileType {
	case "script":
		return "script"
	case "json":
		return "json"
	case "yaml":
		return "yaml"
	case "readme":
		return "readme"
	default:
		return "article"
	}
}
