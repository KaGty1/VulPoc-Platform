package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vulpoc-backend/model"
	"vulpoc-backend/utils"
)

type Context struct {
	SourceName        string
	SourceType        string
	SourceRoot        string
	IngestedAt        string
	MaxInlineFileSize int64
}

type FileCandidate struct {
	AbsolutePath string
	RelativePath string
	Name         string
	FileType     string
	Size         int64
	Bytes        []byte
}

type DirCandidate struct {
	AbsolutePath string
	RelativePath string
	Name         string
	Files        []FileCandidate
	Subdirs      []string
}

type FileParser interface {
	Name() string
	Priority() int
	Match(FileCandidate) bool
	Parse(Context, FileCandidate) (model.Entry, error)
}

type DirParser interface {
	Name() string
	Priority() int
	Match(DirCandidate) bool
	Parse(Context, DirCandidate) (model.Entry, error)
}

type Registry struct {
	fileParsers []FileParser
	dirParsers  []DirParser
}

func NewRegistry() *Registry {
	registry := &Registry{}
	registry.RegisterDirParser(CVEDirParser{})
	registry.RegisterDirParser(ReadmeRepoParser{})
	registry.RegisterDirParser(BundleDirParser{})
	registry.RegisterFileParser(MarkdownParser{})
	registry.RegisterFileParser(JSONParser{})
	registry.RegisterFileParser(YAMLParser{})
	registry.RegisterFileParser(HTMLParser{})
	registry.RegisterFileParser(PDFParser{})
	registry.RegisterFileParser(ScriptParser{})
	registry.RegisterFileParser(GenericTextParser{})
	return registry
}

func (r *Registry) RegisterFileParser(p FileParser) {
	r.fileParsers = append(r.fileParsers, p)
	sort.SliceStable(r.fileParsers, func(i, j int) bool {
		return r.fileParsers[i].Priority() > r.fileParsers[j].Priority()
	})
}

func (r *Registry) RegisterDirParser(p DirParser) {
	r.dirParsers = append(r.dirParsers, p)
	sort.SliceStable(r.dirParsers, func(i, j int) bool {
		return r.dirParsers[i].Priority() > r.dirParsers[j].Priority()
	})
}

func (r *Registry) ParseFile(ctx Context, candidate FileCandidate) (model.Entry, string, error) {
	for _, p := range r.fileParsers {
		if !p.Match(candidate) {
			continue
		}
		entry, err := p.Parse(ctx, candidate)
		if err != nil {
			return model.Entry{}, p.Name(), err
		}
		entry.ParserName = p.Name()
		return finalizeEntry(ctx, entry, candidate.RelativePath), p.Name(), nil
	}
	return model.Entry{}, "", fmt.Errorf("no parser matched %s", candidate.RelativePath)
}

func (r *Registry) ParseDir(ctx Context, candidate DirCandidate) (model.Entry, string, bool, error) {
	for _, p := range r.dirParsers {
		if !p.Match(candidate) {
			continue
		}
		entry, err := p.Parse(ctx, candidate)
		if err != nil {
			return model.Entry{}, p.Name(), true, err
		}
		entry.ParserName = p.Name()
		return finalizeEntry(ctx, entry, candidate.RelativePath), p.Name(), true, nil
	}
	return model.Entry{}, "", false, nil
}

func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.dirParsers)+len(r.fileParsers))
	for _, p := range r.dirParsers {
		names = append(names, p.Name())
	}
	for _, p := range r.fileParsers {
		names = append(names, p.Name())
	}
	return names
}

func finalizeEntry(ctx Context, entry model.Entry, relPath string) model.Entry {
	entry.SourceName = ctx.SourceName
	entry.SourceType = choose(entry.SourceType, ctx.SourceType)
	entry.SourcePath = filepath.ToSlash(relPath)
	entry.IngestedAt = ctx.IngestedAt
	entry.Tags = utils.UniqueStrings(entry.Tags)
	entry.Aliases = utils.UniqueStrings(entry.Aliases)
	entry.Products = utils.UniqueStrings(entry.Products)
	entry.Versions = utils.UniqueStrings(entry.Versions)
	entry.References = utils.UniqueStrings(entry.References)
	if entry.Title == "" {
		entry.Title = filepath.Base(relPath)
	}
	if entry.Description == "" {
		entry.Description = entry.Summary
	}
	if entry.Summary == "" {
		entry.Summary = utils.Summarize(entry.Description+"\n"+entry.Content+"\n"+entry.POC, 220)
	}
	if entry.CVE == "" {
		entry.CVE = utils.DetectCVE(entry.Title + "\n" + entry.Content + "\n" + entry.Description)
	}
	if entry.FileType == "" {
		entry.FileType = inferEntryFileType(entry.Files, relPath)
	}
	entry.ID = utils.HashID(ctx.SourceName, entry.ParserName, relPath, entry.Title, entry.CVE)
	entry.SearchText = strings.ToLower(strings.Join([]string{
		entry.Title,
		entry.CVE,
		strings.Join(entry.Aliases, " "),
		entry.Description,
		entry.Summary,
		entry.Content,
		entry.POC,
		entry.Exp,
		strings.Join(entry.Tags, " "),
		strings.Join(entry.Products, " "),
		strings.Join(entry.Versions, " "),
		strings.Join(entry.References, " "),
		entry.SourceName,
		entry.SourceType,
		entry.SourcePath,
		entry.FileType,
	}, "\n"))
	for i := range entry.Files {
		entry.Files[i].DownloadURL = fmt.Sprintf("/api/v1/entries/%s/assets?path=%s", entry.ID, entry.Files[i].RelativePath)
	}
	return entry
}

func LoadTextFile(absPath string, maxInlineSize int64) ([]byte, int64, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, 0, err
	}
	size := info.Size()
	if size > maxInlineSize*4 {
		maxInlineSize = maxInlineSize * 4
	}
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, 0, err
	}
	if utils.LooksBinary(data) {
		return nil, size, fmt.Errorf("binary content")
	}
	return data, size, nil
}

func BuildEntryFiles(files []FileCandidate, maxInlineSize int64) []model.EntryFile {
	assets := make([]model.EntryFile, 0, len(files))
	for _, file := range files {
		item := model.EntryFile{
			Name:         file.Name,
			RelativePath: filepath.ToSlash(file.RelativePath),
			FileType:     file.FileType,
			Category:     utils.CategoryFromFileType(file.FileType),
			Language:     utils.LanguageFromName(file.Name),
			Size:         file.Size,
			AbsolutePath: file.AbsolutePath,
		}
		if len(file.Bytes) > 0 && int64(len(file.Bytes)) <= maxInlineSize && utils.IsTextLike(file.Name) {
			item.InlineContent = string(file.Bytes)
		}
		assets = append(assets, item)
	}
	sort.SliceStable(assets, func(i, j int) bool {
		return assets[i].RelativePath < assets[j].RelativePath
	})
	return assets
}

func pickPrimaryContent(files []FileCandidate) *FileCandidate {
	var fallback *FileCandidate
	for _, file := range files {
		if utils.IsReadme(file.Name) {
			copy := file
			return &copy
		}
		if file.FileType == "markdown" {
			copy := file
			return &copy
		}
		if fallback == nil && (file.FileType == "html" || file.FileType == "text" || file.FileType == "json" || file.FileType == "yaml" || file.FileType == "xml") {
			copy := file
			fallback = &copy
		}
	}
	return fallback
}

func pickPrimaryScript(files []FileCandidate) *FileCandidate {
	for _, file := range files {
		if file.FileType == "script" {
			copy := file
			return &copy
		}
	}
	return nil
}

func inferEntryFileType(files []model.EntryFile, relPath string) string {
	if len(files) > 0 {
		for _, file := range files {
			switch file.FileType {
			case "readme", "markdown":
				return "markdown"
			case "json", "yaml", "html", "xml", "csv", "script", "text":
				return file.FileType
			case "pdf":
				return "pdf"
			}
		}
	}
	name := filepath.Base(relPath)
	if fileType := utils.FileTypeFromExt(name); fileType != "" {
		return fileType
	}
	return "bundle"
}

func choose(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
