package sshcfg

import (
	"maps"
	"slices"
)

func sortedKeys(m map[string]string) []string { return slices.Sorted(maps.Keys(m)) }
