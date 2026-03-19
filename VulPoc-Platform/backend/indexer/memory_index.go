package indexer

import (
	"sort"
	"strings"

	"vulpoc-backend/model"
)

type MemoryIndex struct {
	entries []model.Entry
}

func New(entries []model.Entry) *MemoryIndex {
	return &MemoryIndex{entries: append([]model.Entry(nil), entries...)}
}

func (m *MemoryIndex) Search(query model.SearchQuery) model.SearchResult {
	page := query.Page
	if page < 1 {
		page = 1
	}
	pageSize := query.PageSize
	if pageSize < 1 {
		pageSize = 12
	}
	if pageSize > 100 {
		pageSize = 100
	}

	keyword := strings.ToLower(strings.TrimSpace(query.Keyword))
	cve := strings.ToUpper(strings.TrimSpace(query.CVE))
	tag := strings.ToLower(strings.TrimSpace(query.Tag))
	source := strings.ToLower(strings.TrimSpace(query.Source))
	fileType := strings.ToLower(strings.TrimSpace(query.FileType))

	matched := make([]model.Entry, 0, len(m.entries))
	for _, entry := range m.entries {
		if cve != "" && !strings.Contains(strings.ToUpper(entry.CVE), cve) && !strings.Contains(strings.ToUpper(entry.SearchText), cve) {
			continue
		}
		if tag != "" && !containsFold(entry.Tags, tag) {
			continue
		}
		if source != "" && !strings.Contains(strings.ToLower(entry.SourceName), source) {
			continue
		}
		if fileType != "" && !strings.Contains(strings.ToLower(entry.FileType), fileType) {
			continue
		}

		score := scoreEntry(entry, keyword, cve)
		if keyword != "" && score == 0 {
			continue
		}
		entry.MatchScore = score
		matched = append(matched, entry)
	}

	sort.SliceStable(matched, func(i, j int) bool {
		if matched[i].MatchScore == matched[j].MatchScore {
			if matched[i].UpdatedAt == matched[j].UpdatedAt {
				return matched[i].Title < matched[j].Title
			}
			return matched[i].UpdatedAt > matched[j].UpdatedAt
		}
		return matched[i].MatchScore > matched[j].MatchScore
	})

	start := (page - 1) * pageSize
	if start > len(matched) {
		start = len(matched)
	}
	end := start + pageSize
	if end > len(matched) {
		end = len(matched)
	}

	summaries := make([]model.EntrySummary, 0, end-start)
	for _, entry := range matched[start:end] {
		summaries = append(summaries, entry.ToSummary())
	}

	return model.SearchResult{
		List:     summaries,
		Total:    len(matched),
		Page:     page,
		PageSize: pageSize,
	}
}

func (m *MemoryIndex) Tags() []model.TagInfo {
	counts := make(map[string]int)
	for _, entry := range m.entries {
		for _, tag := range entry.Tags {
			counts[tag]++
		}
	}
	items := make([]model.TagInfo, 0, len(counts))
	for name, count := range counts {
		items = append(items, model.TagInfo{Name: name, Count: count})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	return items
}

func scoreEntry(entry model.Entry, keyword, cve string) int {
	if keyword == "" && cve == "" {
		return 1
	}
	score := 0
	if cve != "" {
		switch {
		case strings.EqualFold(entry.CVE, cve):
			score += 180
		case strings.Contains(strings.ToUpper(entry.SearchText), cve):
			score += 100
		}
	}
	if keyword == "" {
		return score
	}
	terms := strings.Fields(keyword)
	if len(terms) == 0 {
		terms = []string{keyword}
	}
	title := strings.ToLower(entry.Title)
	summary := strings.ToLower(entry.Summary)
	content := strings.ToLower(entry.Content)
	for _, term := range terms {
		switch {
		case strings.Contains(title, term):
			score += 80
		case strings.Contains(summary, term):
			score += 35
		case strings.Contains(content, term):
			score += 20
		case strings.Contains(strings.ToLower(entry.SearchText), term):
			score += 10
		}
		if containsFold(entry.Tags, term) {
			score += 25
		}
		if containsFold(entry.Products, term) {
			score += 25
		}
	}
	return score
}

func containsFold(items []string, keyword string) bool {
	for _, item := range items {
		if strings.Contains(strings.ToLower(item), keyword) {
			return true
		}
	}
	return false
}
