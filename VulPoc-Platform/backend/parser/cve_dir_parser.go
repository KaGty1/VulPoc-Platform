package parser

import (
	"strings"

	"vulpoc-backend/model"
)

type CVEDirParser struct{}

func (CVEDirParser) Name() string  { return "CVEDirParser" }
func (CVEDirParser) Priority() int { return 120 }
func (CVEDirParser) Match(dir DirCandidate) bool {
	if !strings.Contains(strings.ToUpper(dir.RelativePath), "CVE-") {
		return false
	}
	return hasPrimaryBundleFiles(dir)
}

func (CVEDirParser) Parse(ctx Context, dir DirCandidate) (model.Entry, error) {
	return buildBundleEntry(ctx, dir, "repo")
}
