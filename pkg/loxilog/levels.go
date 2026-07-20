package loxilog

import (
	"strings"
	"sync/atomic"

	"github.com/rs/zerolog"
)

// Category represents a log category for per-category level control.
type Category int

const (
	CatNetwork   Category = 0
	CatAuth      Category = 1
	CatCluster   Category = 2
	CatDataplane Category = 3
	CatAI        Category = 4
	CatSystem    Category = 5
	catCount     Category = 6
)

// categoryNames maps Category values to their string names.
var categoryNames = map[Category]string{
	CatNetwork:   "network",
	CatAuth:      "auth",
	CatCluster:   "cluster",
	CatDataplane: "dataplane",
	CatAI:        "ai",
	CatSystem:    "system",
}

// categoryFromStringMap is the reverse lookup for CategoryFromString.
var categoryFromStringMap map[string]Category

func init() {
	// Initialize all category levels to DebugLevel (matching existing --loglevel default).
	for i := Category(0); i < catCount; i++ {
		categoryLevels[i].Store(int32(zerolog.DebugLevel))
	}

	// Build reverse lookup map.
	categoryFromStringMap = make(map[string]Category, len(categoryNames))
	for cat, name := range categoryNames {
		categoryFromStringMap[name] = cat
	}
}

// categoryLevels holds the current log level for each category.
// Access is lock-free via atomic operations.
var categoryLevels [catCount]atomic.Int32

// SetCategoryLevel atomically sets the minimum log level for a category.
func SetCategoryLevel(cat Category, level zerolog.Level) {
	if cat >= 0 && cat < catCount {
		categoryLevels[cat].Store(int32(level))
	}
}

// GetCategoryLevel atomically reads the current minimum log level for a category.
func GetCategoryLevel(cat Category) zerolog.Level {
	if cat >= 0 && cat < catCount {
		return zerolog.Level(categoryLevels[cat].Load())
	}
	return zerolog.DebugLevel
}

// CategoryName returns the string name for a category.
func CategoryName(cat Category) string {
	if name, ok := categoryNames[cat]; ok {
		return name
	}
	return "unknown"
}

// CategoryFromString parses a string into a Category.
// Returns the category and true if found, or (0, false) if not.
func CategoryFromString(s string) (Category, bool) {
	cat, ok := categoryFromStringMap[strings.ToLower(s)]
	return cat, ok
}
