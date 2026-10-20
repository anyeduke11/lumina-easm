// Package main 是迁移工具（WP-M0-03；替代 Makefile 手写 psql 清单）。
//
// 迁移文件按文件名排序；schema_migrations 记录已应用版本。迁移文件内的
// BEGIN/COMMIT 会被剥离，由工具统一事务包裹，避免部分应用。
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	_ "github.com/lib/pq"
)

type migration struct {
	Version string
	Path    string
	SQL     string
}

var (
	txBegin = regexp.MustCompile(`(?is)\bBEGIN\s*;`)
	txEnd   = regexp.MustCompile(`(?is)COMMIT\s*;\s*$`)
)

func stripTx(s string) string {
	s = txBegin.ReplaceAllString(s, "")
	s = txEnd.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

func load(dir string) ([]migration, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	out := make([]migration, 0, len(files))
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{
			Version: strings.TrimSuffix(filepath.Base(f), ".sql"),
			Path:    f,
			SQL:     stripTx(string(b)),
		})
	}
	return out, nil
}

func open(dsn string) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("EASM_MIGRATE_DSN 未设置（迁移需要 DDL 权限的管理员 DSN）")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func ensureTable(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
	return err
}

func applied(db *sql.DB) (map[string]bool, error) {
	rows, err := db.Query("SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

func up(db *sql.DB, ms []migration) error {
	if err := ensureTable(db); err != nil {
		return err
	}
	done, err := applied(db)
	if err != nil {
		return err
	}
	n := 0
	for _, m := range ms {
		if done[m.Version] {
			continue
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.SQL); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s: %w", m.Version, err)
		}
		if _, err := tx.Exec("INSERT INTO schema_migrations(version) VALUES($1)", m.Version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("%s: record version: %w", m.Version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("%s: commit: %w", m.Version, err)
		}
		fmt.Println("applied", m.Version)
		n++
	}
	fmt.Printf("migrate up: %d applied, %d total\n", n, len(ms))
	return nil
}

func baseline(db *sql.DB, ms []migration) error {
	if err := ensureTable(db); err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, m := range ms {
		if _, err := tx.Exec("INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING", m.Version); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("migrate baseline: %d versions marked applied (not executed)\n", len(ms))
	return nil
}

func status(db *sql.DB, ms []migration) error {
	if err := ensureTable(db); err != nil {
		return err
	}
	done, err := applied(db)
	if err != nil {
		return err
	}
	for _, m := range ms {
		state := "pending"
		if done[m.Version] {
			state = "applied"
		}
		fmt.Printf("%-40s %s\n", m.Version, state)
	}
	return nil
}

func main() {
	dir := flag.String("dir", "migrations", "migration directory")
	dsn := flag.String("dsn", os.Getenv("EASM_MIGRATE_DSN"), "admin DSN (DDL)")
	yes := flag.Bool("yes", false, "confirm baseline (mark existing DB as applied without executing)")
	flag.Parse()
	cmd := "up"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	ms, err := load(*dir)
	if err != nil {
		log.Fatalf("load migrations: %v", err)
	}
	if len(ms) == 0 {
		log.Fatalf("no migrations found in %s", *dir)
	}
	if cmd == "list" {
		for _, m := range ms {
			fmt.Println(m.Version)
		}
		return
	}
	db, err := open(*dsn)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer db.Close()
	switch cmd {
	case "up":
		err = up(db, ms)
	case "status":
		err = status(db, ms)
	case "plan":
		var done map[string]bool
		if err = ensureTable(db); err == nil {
			if done, err = applied(db); err == nil {
				for _, m := range ms {
					if !done[m.Version] {
						fmt.Println(m.Version)
					}
				}
			}
		}
	case "baseline":
		if !*yes {
			log.Fatalf("baseline 会把现有迁移标记为已应用而不执行；确认请加 -yes")
		}
		err = baseline(db, ms)
	default:
		log.Fatalf("unknown command %q (up|status|plan|baseline|list)", cmd)
	}
	if err != nil {
		log.Fatalf("%s: %v", cmd, err)
	}
}
