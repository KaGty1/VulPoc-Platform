package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Source struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type App struct {
	ServerPort        string   `json:"server_port"`
	FrontendDist      string   `json:"frontend_dist"`
	MaxInlineFileSize int64    `json:"max_inline_file_size"`
	Sources           []Source `json:"sources"`
}

func Load() (App, error) {
	configPath := os.Getenv("VULPOC_CONFIG")
	if configPath == "" {
		configPath = filepath.Join("config", "app.json")
	}
	cfg := defaultConfig()
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return App{}, fmt.Errorf("parse config %s: %w", configPath, err)
		}
	} else if !os.IsNotExist(err) {
		return App{}, fmt.Errorf("read config %s: %w", configPath, err)
	}

	overrideFromEnv(&cfg)

	baseDir, err := os.Getwd()
	if err != nil {
		return App{}, fmt.Errorf("get working dir: %w", err)
	}

	for i := range cfg.Sources {
		if !filepath.IsAbs(cfg.Sources[i].Path) {
			cfg.Sources[i].Path = filepath.Clean(filepath.Join(baseDir, cfg.Sources[i].Path))
		}
		cfg.Sources[i].Type = strings.TrimSpace(cfg.Sources[i].Type)
		if cfg.Sources[i].Type == "" {
			cfg.Sources[i].Type = "repo"
		}
	}

	if !filepath.IsAbs(cfg.FrontendDist) {
		cfg.FrontendDist = filepath.Clean(filepath.Join(baseDir, cfg.FrontendDist))
	}
	if cfg.ServerPort == "" {
		cfg.ServerPort = "8080"
	}
	if cfg.MaxInlineFileSize <= 0 {
		cfg.MaxInlineFileSize = 256 * 1024
	}

	return cfg, nil
}

func defaultConfig() App {
	return App{
		ServerPort:        "8080",
		FrontendDist:      "../frontend/dist",
		MaxInlineFileSize: 256 * 1024,
		Sources: []Source{
			{Name: "Vulnerability Wiki PoC", Path: "../../Vulnerability-Wiki-PoC-main", Type: "repo"},
			{Name: "Awesome POC", Path: "../../Awesome-POC-master", Type: "repo"},
			{Name: "域渗透指南", Path: "../../域渗透攻防", Type: "guide"},
		},
	}
}

func overrideFromEnv(cfg *App) {
	if port := strings.TrimSpace(os.Getenv("VULPOC_PORT")); port != "" {
		cfg.ServerPort = port
	}
	if dist := strings.TrimSpace(os.Getenv("VULPOC_FRONTEND_DIST")); dist != "" {
		cfg.FrontendDist = dist
	}
	if raw := strings.TrimSpace(os.Getenv("VULPOC_SOURCE_DIRS")); raw != "" {
		items := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';'
		})
		sources := make([]Source, 0, len(items))
		for index, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			name := filepath.Base(item)
			sources = append(sources, Source{
				Name: fmt.Sprintf("%s-%d", name, index+1),
				Path: item,
				Type: "repo",
			})
		}
		if len(sources) > 0 {
			cfg.Sources = sources
		}
	}
}
