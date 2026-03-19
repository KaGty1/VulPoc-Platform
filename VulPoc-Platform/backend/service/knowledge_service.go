package service

import (
	"vulpoc-backend/indexer"
	"vulpoc-backend/model"
	"vulpoc-backend/repository"
)

type KnowledgeService struct {
	repo  *repository.MemoryRepository
	index *indexer.MemoryIndex
}

func NewKnowledgeService(repo *repository.MemoryRepository, index *indexer.MemoryIndex) *KnowledgeService {
	return &KnowledgeService{repo: repo, index: index}
}

func (s *KnowledgeService) SearchEntries(query model.SearchQuery) model.SearchResult {
	return s.index.Search(query)
}

func (s *KnowledgeService) GetEntry(id string) (model.Entry, error) {
	return s.repo.GetEntry(id)
}

func (s *KnowledgeService) GetSources() []model.SourceInfo {
	return s.repo.ListSources()
}

func (s *KnowledgeService) GetTags() []model.TagInfo {
	return s.index.Tags()
}

func (s *KnowledgeService) GetStats() model.Stats {
	return s.repo.GetStats()
}

func (s *KnowledgeService) GetAsset(id, path string) (model.EntryFile, error) {
	return s.repo.GetAsset(id, path)
}
