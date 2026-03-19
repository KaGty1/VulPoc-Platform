package repository

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"vulpoc-backend/model"
)

type MemoryRepository struct {
	mu      sync.RWMutex
	entries []model.Entry
	byID    map[string]model.Entry
	sources []model.SourceInfo
	stats   model.Stats
}

func NewMemoryRepository(entries []model.Entry, sources []model.SourceInfo, importStats model.ImportStats, parserNames []string) *MemoryRepository {
	byID := make(map[string]model.Entry, len(entries))
	fileTypeCounts := make(map[string]int)
	for i := range entries {
		byID[entries[i].ID] = entries[i]
		fileTypeCounts[strings.ToLower(entries[i].FileType)]++
	}

	fileTypes := make([]model.NamedCount, 0, len(fileTypeCounts))
	for name, count := range fileTypeCounts {
		fileTypes = append(fileTypes, model.NamedCount{Name: name, Count: count})
	}
	sort.SliceStable(fileTypes, func(i, j int) bool {
		if fileTypes[i].Count == fileTypes[j].Count {
			return fileTypes[i].Name < fileTypes[j].Name
		}
		return fileTypes[i].Count > fileTypes[j].Count
	})

	stats := model.Stats{
		TotalEntries:     len(entries),
		SourceCount:      len(sources),
		ParserCount:      len(parserNames),
		SupportedParsers: append([]string(nil), parserNames...),
		Import:           importStats,
		FileTypes:        fileTypes,
		Sources:          append([]model.SourceInfo(nil), sources...),
		LastIngested:     time.Now().Format(time.RFC3339),
	}

	return &MemoryRepository{
		entries: append([]model.Entry(nil), entries...),
		byID:    byID,
		sources: append([]model.SourceInfo(nil), sources...),
		stats:   stats,
	}
}

func (r *MemoryRepository) ListEntries() []model.Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]model.Entry(nil), r.entries...)
}

func (r *MemoryRepository) GetEntry(id string) (model.Entry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.byID[id]
	if !ok {
		return model.Entry{}, errors.New("entry not found")
	}
	return entry, nil
}

func (r *MemoryRepository) GetAsset(id, relPath string) (model.EntryFile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.byID[id]
	if !ok {
		return model.EntryFile{}, errors.New("entry not found")
	}
	for _, file := range entry.Files {
		if file.RelativePath == relPath {
			return file, nil
		}
	}
	return model.EntryFile{}, errors.New("asset not found")
}

func (r *MemoryRepository) ListSources() []model.SourceInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]model.SourceInfo(nil), r.sources...)
}

func (r *MemoryRepository) GetStats() model.Stats {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.stats
}
