package template

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadFromDir loads all .yaml/.yml templates from a directory (recursive).
func LoadFromDir(dir string) ([]*Template, error) {
	var templates []*Template
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		tmpl, err := Parse(raw)
		if err != nil {
			return nil
		}
		if err := tmpl.Compile(); err != nil {
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}

// LoadFromFS loads all .yaml/.yml templates from an fs.FS.
func LoadFromFS(fsys fs.FS, root string) ([]*Template, error) {
	var templates []*Template
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}

		raw, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil
		}

		tmpl, err := Parse(raw)
		if err != nil {
			return nil
		}
		if err := tmpl.Compile(); err != nil {
			return nil
		}
		templates = append(templates, tmpl)
		return nil
	})
	return templates, err
}