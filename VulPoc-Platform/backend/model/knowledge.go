package model

type Entry struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	CVE         string      `json:"cve"`
	Aliases     []string    `json:"aliases"`
	Description string      `json:"description"`
	Summary     string      `json:"summary"`
	Content     string      `json:"content"`
	POC         string      `json:"poc"`
	Exp         string      `json:"exp"`
	Tags        []string    `json:"tags"`
	Products    []string    `json:"products"`
	Versions    []string    `json:"versions"`
	References  []string    `json:"references"`
	SourceName  string      `json:"source_name"`
	SourceType  string      `json:"source_type"`
	SourcePath  string      `json:"source_path"`
	FileType    string      `json:"file_type"`
	Author      string      `json:"author"`
	PublishedAt string      `json:"published_at"`
	UpdatedAt   string      `json:"updated_at"`
	IngestedAt  string      `json:"ingested_at"`
	ParserName  string      `json:"parser_name"`
	Files       []EntryFile `json:"files,omitempty"`
	MatchScore  int         `json:"match_score,omitempty"`
	SearchText  string      `json:"-"`
}

type EntryFile struct {
	Name          string `json:"name"`
	RelativePath  string `json:"relative_path"`
	FileType      string `json:"file_type"`
	Category      string `json:"category"`
	Language      string `json:"language"`
	Size          int64  `json:"size"`
	InlineContent string `json:"inline_content,omitempty"`
	DownloadURL   string `json:"download_url"`
	AbsolutePath  string `json:"-"`
}

type EntrySummary struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	CVE         string   `json:"cve"`
	Summary     string   `json:"summary"`
	Tags        []string `json:"tags"`
	Products    []string `json:"products"`
	SourceName  string   `json:"source_name"`
	SourceType  string   `json:"source_type"`
	SourcePath  string   `json:"source_path"`
	FileType    string   `json:"file_type"`
	ParserName  string   `json:"parser_name"`
	PublishedAt string   `json:"published_at"`
	UpdatedAt   string   `json:"updated_at"`
	MatchScore  int      `json:"match_score"`
}

type SearchQuery struct {
	Keyword  string
	CVE      string
	Tag      string
	Source   string
	FileType string
	Page     int
	PageSize int
}

type SearchResult struct {
	List     []EntrySummary `json:"list"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
}

type SourceInfo struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Path         string `json:"path"`
	Entries      int    `json:"entries"`
	FilesScanned int    `json:"files_scanned"`
	FilesSkipped int    `json:"files_skipped"`
	ParseFailed  int    `json:"parse_failed"`
	LastIngested string `json:"last_ingested"`
}

type TagInfo struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ImportStats struct {
	EntriesCreated     int `json:"entries_created"`
	DirectoriesScanned int `json:"directories_scanned"`
	FilesScanned       int `json:"files_scanned"`
	FilesSkipped       int `json:"files_skipped"`
	ParseFailed        int `json:"parse_failed"`
}

type Stats struct {
	TotalEntries     int          `json:"total_entries"`
	SourceCount      int          `json:"source_count"`
	ParserCount      int          `json:"parser_count"`
	SupportedParsers []string     `json:"supported_parsers"`
	Import           ImportStats  `json:"import"`
	FileTypes        []NamedCount `json:"file_types"`
	Sources          []SourceInfo `json:"sources"`
	LastIngested     string       `json:"last_ingested"`
}

func (e Entry) ToSummary() EntrySummary {
	return EntrySummary{
		ID:          e.ID,
		Title:       e.Title,
		CVE:         e.CVE,
		Summary:     e.Summary,
		Tags:        append([]string(nil), e.Tags...),
		Products:    append([]string(nil), e.Products...),
		SourceName:  e.SourceName,
		SourceType:  e.SourceType,
		SourcePath:  e.SourcePath,
		FileType:    e.FileType,
		ParserName:  e.ParserName,
		PublishedAt: e.PublishedAt,
		UpdatedAt:   e.UpdatedAt,
		MatchScore:  e.MatchScore,
	}
}
