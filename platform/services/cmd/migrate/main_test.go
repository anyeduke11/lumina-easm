package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStripTx(t *testing.T) {
	in := "-- migration comment\nBEGIN;\nSELECT 1;\nCOMMIT;\n"
	if got := stripTx(in); got != "-- migration comment\n\nSELECT 1;" {
		t.Fatalf("stripTx = %q", got)
	}
}

func TestLoadSortedAndStrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "002_b.sql"), []byte("BEGIN;\nSELECT 2;\nCOMMIT;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "001_a.sql"), []byte("SELECT 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	ms, err := load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Version != "001_a" || ms[1].Version != "002_b" {
		t.Fatalf("migrations not sorted: %+v", ms)
	}
	if ms[1].SQL != "SELECT 2;" {
		t.Fatalf("BEGIN/COMMIT not stripped: %q", ms[1].SQL)
	}
}
