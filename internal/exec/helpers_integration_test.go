//go:build integration

package exec

import "os"

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	return string(b), err
}
