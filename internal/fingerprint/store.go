package fingerprint

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/earthcake2233/banner-fingerprint/internal/fingerprint/builtin"
)

// Store holds the active engine and can hot-reload the rules from disk.
//
// Load priority:
//  1. the path passed in (file or directory),
//  2. the rule set embedded in the binary.
//
// A broken external rule file never takes the service down: the previous engine
// (or the embedded one) keeps serving.
type Store struct {
	path string
	log  *slog.Logger
	cur  atomic.Pointer[Engine]

	lastMod   atomic.Int64
	lastSize  atomic.Int64
	loadedAt  atomic.Int64
	reloadErr atomic.Pointer[string]
}

// NewStore loads the rules and returns a ready store.
func NewStore(path string, log *slog.Logger) (*Store, error) {
	s := &Store{path: path, log: log}
	if err := s.load(); err != nil {
		if path == "" {
			return nil, err
		}
		log.Warn("external rules unusable, falling back to embedded rules", "path", path, "err", err)
		s.path = ""
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Engine returns the currently active engine.
func (s *Store) Engine() *Engine { return s.cur.Load() }

// LoadedAt returns when the active rules were loaded.
func (s *Store) LoadedAt() time.Time { return time.Unix(s.loadedAt.Load(), 0) }

// ReloadError returns the last reload failure, if any.
func (s *Store) ReloadError() string {
	if p := s.reloadErr.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *Store) load() error {
	var (
		rs  *RuleSet
		err error
	)
	if s.path == "" {
		rs, err = LoadRuleSet("embedded:"+builtin.Name, builtin.RulesYAML)
	} else {
		rs, err = LoadPath(s.path)
	}
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	s.cur.Store(NewEngine(rs))
	s.loadedAt.Store(time.Now().Unix())
	if info, err := os.Stat(s.path); err == nil {
		s.lastMod.Store(info.ModTime().UnixNano())
		s.lastSize.Store(info.Size())
	}
	s.reloadErr.Store(nil)
	s.log.Info("rules loaded", "source", rs.Source, "rules", len(rs.Rules))
	return nil
}

// Reload forces a rules reload (used by SIGHUP and the file watcher).
func (s *Store) Reload() error {
	if err := s.load(); err != nil {
		msg := err.Error()
		s.reloadErr.Store(&msg)
		return err
	}
	return nil
}

// Watch polls the rule path and reloads it when it changes on disk. It returns
// when ctx is done.
func (s *Store) Watch(stop <-chan struct{}, every time.Duration) {
	if s.path == "" {
		return
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			info, err := os.Stat(s.path)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					s.log.Debug("rules stat failed", "err", err)
				}
				continue
			}
			if info.ModTime().UnixNano() == s.lastMod.Load() && info.Size() == s.lastSize.Load() {
				continue
			}
			if err := s.Reload(); err != nil {
				s.log.Error("rules reload failed, keeping previous rules", "err", err)
				// Remember the seen state so we do not log on every tick.
				s.lastMod.Store(info.ModTime().UnixNano())
				s.lastSize.Store(info.Size())
				continue
			}
			s.log.Info("rules reloaded", "source", s.Engine().Source(), "rules", len(s.Engine().Rules()))
		}
	}
}
