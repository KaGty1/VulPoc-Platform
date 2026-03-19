package ingest

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"vulpoc-backend/config"
	"vulpoc-backend/model"
	"vulpoc-backend/parser"
	"vulpoc-backend/utils"
)

type Result struct {
	Entries []model.Entry
	Sources []model.SourceInfo
	Stats   model.ImportStats
}

var (
	markdownAssetPattern = regexp.MustCompile(`!\[[^\]]*]\(([^)]+)\)`)
	htmlImagePattern     = regexp.MustCompile(`(?i)<img[^>]+src=["']([^"']+)["']`)
)

func LoadSources(cfg config.App, registry *parser.Registry) (Result, error) {
	result := Result{
		Entries: make([]model.Entry, 0, 2048),
		Sources: make([]model.SourceInfo, 0, len(cfg.Sources)),
	}

	for _, source := range cfg.Sources {
		info, err := loadSingleSource(cfg, registry, source)
		if err != nil {
			return Result{}, err
		}
		result.Entries = append(result.Entries, info.entries...)
		result.Sources = append(result.Sources, info.summary)
		result.Stats.EntriesCreated += len(info.entries)
		result.Stats.DirectoriesScanned += info.directoriesScanned
		result.Stats.FilesScanned += info.summary.FilesScanned
		result.Stats.FilesSkipped += info.summary.FilesSkipped
		result.Stats.ParseFailed += info.summary.ParseFailed
	}

	sort.SliceStable(result.Entries, func(i, j int) bool {
		if result.Entries[i].CVE == result.Entries[j].CVE {
			return result.Entries[i].Title < result.Entries[j].Title
		}
		return result.Entries[i].CVE > result.Entries[j].CVE
	})
	return result, nil
}

type sourceLoadResult struct {
	entries            []model.Entry
	summary            model.SourceInfo
	directoriesScanned int
}

func loadSingleSource(cfg config.App, registry *parser.Registry, source config.Source) (sourceLoadResult, error) {
	cleanRoot := filepath.Clean(source.Path)
	stat, err := os.Stat(cleanRoot)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("source skipped, path not found: %s", cleanRoot)
			return sourceLoadResult{
				summary: model.SourceInfo{
					Name:         source.Name,
					Type:         source.Type,
					Path:         cleanRoot,
					LastIngested: time.Now().Format(time.RFC3339),
				},
			}, nil
		}
		return sourceLoadResult{}, fmt.Errorf("stat source %s: %w", cleanRoot, err)
	}
	if !stat.IsDir() {
		return sourceLoadResult{}, fmt.Errorf("source %s is not directory", cleanRoot)
	}

	ctx := parser.Context{
		SourceName:        source.Name,
		SourceType:        source.Type,
		SourceRoot:        cleanRoot,
		IngestedAt:        time.Now().Format(time.RFC3339),
		MaxInlineFileSize: cfg.MaxInlineFileSize,
	}

	entries := make([]model.Entry, 0, 1024)
	sourceInfo := model.SourceInfo{
		Name:         source.Name,
		Type:         source.Type,
		Path:         cleanRoot,
		LastIngested: ctx.IngestedAt,
	}
	directoriesScanned := 0

	walkErr := filepath.WalkDir(cleanRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			sourceInfo.ParseFailed++
			return nil
		}

		if d.IsDir() {
			if shouldSkipDir(path, cleanRoot) {
				return filepath.SkipDir
			}
			directoriesScanned++
			if path == cleanRoot {
				return nil
			}

			candidate, ok, err := buildDirCandidate(path, cleanRoot, cfg.MaxInlineFileSize, &sourceInfo)
			if err != nil {
				sourceInfo.ParseFailed++
				return nil
			}
			if !ok {
				return nil
			}

			entry, _, matched, err := registry.ParseDir(ctx, candidate)
			if err != nil {
				sourceInfo.ParseFailed++
				return filepath.SkipDir
			}
			if matched {
				entries = append(entries, entry)
				return filepath.SkipDir
			}
			return nil
		}

		if !shouldParseStandaloneFile(path) {
			sourceInfo.FilesSkipped++
			return nil
		}
		candidate, err := buildFileCandidate(path, cleanRoot, cfg.MaxInlineFileSize)
		if err != nil {
			sourceInfo.FilesSkipped++
			return nil
		}
		sourceInfo.FilesScanned++
		entry, _, err := registry.ParseFile(ctx, candidate)
		if err != nil {
			sourceInfo.ParseFailed++
			return nil
		}
		entry.Files = buildStandaloneEntryFiles(cleanRoot, entry, candidate, cfg.MaxInlineFileSize)
		for i := range entry.Files {
			entry.Files[i].DownloadURL = fmt.Sprintf("/api/v1/entries/%s/assets?path=%s", entry.ID, entry.Files[i].RelativePath)
		}
		entries = append(entries, entry)
		return nil
	})
	if walkErr != nil {
		return sourceLoadResult{}, walkErr
	}

	dedupedEntries := dedupeEntries(entries)
	sourceInfo.Entries = len(dedupedEntries)
	return sourceLoadResult{
		entries:            dedupedEntries,
		summary:            sourceInfo,
		directoriesScanned: directoriesScanned,
	}, nil
}

func buildDirCandidate(dirPath, sourceRoot string, maxInlineSize int64, stats *model.SourceInfo) (parser.DirCandidate, bool, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return parser.DirCandidate{}, false, err
	}

	subdirs := make([]string, 0, len(entries))
	hasPotentialContent := false
	immediateContentCount := 0
	hasReadme := false
	hasCVE := strings.Contains(strings.ToUpper(filepath.Base(dirPath)), "CVE-") || strings.Contains(strings.ToUpper(filepath.ToSlash(dirPath)), "CVE-")
	for _, entry := range entries {
		if entry.IsDir() {
			subdirs = append(subdirs, entry.Name())
			continue
		}
		if utils.IsSupportedContentFile(entry.Name()) {
			hasPotentialContent = true
			immediateContentCount++
			hasReadme = hasReadme || utils.IsReadme(entry.Name())
		}
	}
	if !hasPotentialContent {
		return parser.DirCandidate{}, false, nil
	}
	if immediateContentCount > 3 && !hasReadme && !hasCVE {
		return parser.DirCandidate{}, false, nil
	}

	files := make([]parser.FileCandidate, 0, len(entries))
	err = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			if path != dirPath && shouldSkipDir(path, dirPath) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !utils.IsSupportedContentFile(name) && !utils.IsBundleAsset(name) {
			stats.FilesSkipped++
			return nil
		}
		if utils.IsSupportedContentFile(name) {
			candidate, err := buildFileCandidate(path, sourceRoot, maxInlineSize)
			if err != nil {
				stats.FilesSkipped++
				return nil
			}
			stats.FilesScanned++
			files = append(files, candidate)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			stats.FilesSkipped++
			return nil
		}
		rel, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			stats.FilesSkipped++
			return nil
		}
		stats.FilesScanned++
		files = append(files, parser.FileCandidate{
			AbsolutePath: path,
			RelativePath: filepath.ToSlash(rel),
			Name:         filepath.Base(path),
			FileType:     utils.FileTypeFromExt(name),
			Size:         info.Size(),
		})
		return nil
	})
	if err != nil {
		return parser.DirCandidate{}, false, err
	}
	if len(files) == 0 {
		return parser.DirCandidate{}, false, nil
	}
	rel, err := filepath.Rel(sourceRoot, dirPath)
	if err != nil {
		return parser.DirCandidate{}, false, err
	}
	return parser.DirCandidate{
		AbsolutePath: dirPath,
		RelativePath: filepath.ToSlash(rel),
		Name:         filepath.Base(dirPath),
		Files:        files,
		Subdirs:      subdirs,
	}, true, nil
}

func buildFileCandidate(path, sourceRoot string, maxInlineSize int64) (parser.FileCandidate, error) {
	fileType := utils.FileTypeFromExt(path)
	rel, err := filepath.Rel(sourceRoot, path)
	if err != nil {
		return parser.FileCandidate{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return parser.FileCandidate{}, err
	}

	candidate := parser.FileCandidate{
		AbsolutePath: path,
		RelativePath: filepath.ToSlash(rel),
		Name:         filepath.Base(path),
		FileType:     fileType,
		Size:         info.Size(),
	}

	if utils.IsTextLike(path) {
		data, size, err := parser.LoadTextFile(path, maxInlineSize)
		if err != nil {
			return parser.FileCandidate{}, err
		}
		candidate.Size = size
		candidate.Bytes = data
	}

	return candidate, nil
}

func shouldSkipDir(path, root string) bool {
	if path == root {
		return false
	}
	name := strings.ToLower(filepath.Base(path))
	switch name {
	case ".git", "node_modules", "dist", "build", "vendor", ".idea", ".vscode":
		return true
	}
	return strings.HasPrefix(name, ".")
}

func shouldParseStandaloneFile(path string) bool {
	name := filepath.Base(path)
	return utils.IsSupportedContentFile(name)
}

func dedupeEntries(entries []model.Entry) []model.Entry {
	seen := make(map[string]model.Entry, len(entries))
	for _, entry := range entries {
		if current, ok := seen[entry.ID]; ok {
			if len(current.Content) >= len(entry.Content) {
				continue
			}
		}
		seen[entry.ID] = entry
	}
	result := make([]model.Entry, 0, len(seen))
	for _, entry := range seen {
		result = append(result, entry)
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Title < result[j].Title
	})
	return result
}

func buildStandaloneEntryFiles(sourceRoot string, entry model.Entry, candidate parser.FileCandidate, maxInlineSize int64) []model.EntryFile {
	files := []parser.FileCandidate{candidate}
	seen := map[string]struct{}{
		filepath.ToSlash(candidate.RelativePath): {},
	}

	for _, ref := range extractReferencedAssetPaths(entry.Content, candidate.RelativePath) {
		if _, ok := seen[ref]; ok {
			continue
		}
		asset := buildAssetCandidate(sourceRoot, ref, maxInlineSize)
		if asset == nil {
			continue
		}
		seen[ref] = struct{}{}
		files = append(files, *asset)
	}

	return parser.BuildEntryFiles(files, maxInlineSize)
}

func extractReferencedAssetPaths(content, baseRelativePath string) []string {
	matches := make([]string, 0, 8)
	for _, item := range markdownAssetPattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			matches = append(matches, item[1])
		}
	}
	for _, item := range htmlImagePattern.FindAllStringSubmatch(content, -1) {
		if len(item) > 1 {
			matches = append(matches, item[1])
		}
	}

	baseDir := path.Dir(filepath.ToSlash(baseRelativePath))
	results := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, ref := range matches {
		ref = strings.TrimSpace(ref)
		if ref == "" || strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "#") {
			continue
		}
		cleanRef := path.Clean(path.Join(baseDir, ref))
		if strings.HasPrefix(cleanRef, "../") {
			continue
		}
		if _, ok := seen[cleanRef]; ok {
			continue
		}
		seen[cleanRef] = struct{}{}
		results = append(results, cleanRef)
	}
	return results
}

func buildAssetCandidate(sourceRoot, relativePath string, maxInlineSize int64) *parser.FileCandidate {
	absolutePath := filepath.Join(sourceRoot, filepath.FromSlash(relativePath))
	info, err := os.Stat(absolutePath)
	if err != nil || info.IsDir() {
		return nil
	}

	name := filepath.Base(absolutePath)
	fileType := utils.FileTypeFromExt(name)
	if fileType == "" {
		return nil
	}

	candidate := &parser.FileCandidate{
		AbsolutePath: absolutePath,
		RelativePath: filepath.ToSlash(relativePath),
		Name:         name,
		FileType:     fileType,
		Size:         info.Size(),
	}

	if utils.IsTextLike(name) {
		data, _, err := parser.LoadTextFile(absolutePath, maxInlineSize)
		if err == nil {
			candidate.Bytes = data
		}
	}
	return candidate
}
