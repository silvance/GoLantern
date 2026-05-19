// Package memory provides in-memory implementations of the repository
// interfaces declared in the domain packages. Intended for tests and
// for the early-phase Go server before SQLite parity lands.
//
// All implementations are safe for concurrent use via a per-store
// sync.RWMutex; readers don't block each other but a write blocks
// everything (good enough for tests). The SQLite implementation will
// supersede this for production use.
package memory

import (
	"context"
	"sync"

	"github.com/silvance/golantern/internal/id"
	"github.com/silvance/golantern/internal/project"
	"github.com/silvance/golantern/internal/run"
	"github.com/silvance/golantern/internal/scope"
)

// Store bundles in-memory implementations of every repository, so a
// test or the early-stage server can wire all of them at once.
type Store struct {
	Projects *ProjectRepo
	Scopes   *ScopeRepo
	Runs     *RunRepo
	Audit    *AuditRepo
	Entities *EntityRepo
	Findings *FindingRepo
}

// New constructs an empty Store with all sub-repositories initialized.
func New() *Store {
	return &Store{
		Projects: NewProjectRepo(),
		Scopes:   NewScopeRepo(),
		Runs:     NewRunRepo(),
		Audit:    NewAuditRepo(),
		Entities: NewEntityRepo(),
		Findings: NewFindingRepo(),
	}
}

// ----- Projects --------------------------------------------------------

type ProjectRepo struct {
	mu          sync.RWMutex
	byID        map[string]*project.Project
	idByName    map[string]string // for the UNIQUE(name) invariant
	insertOrder []string          // stable ordering for List
}

func NewProjectRepo() *ProjectRepo {
	return &ProjectRepo{
		byID:     make(map[string]*project.Project),
		idByName: make(map[string]string),
	}
}

func (r *ProjectRepo) Get(_ context.Context, id string) (*project.Project, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[id]
	if !ok {
		return nil, project.ErrNotFound
	}
	return cloneProject(p), nil
}

func (r *ProjectRepo) List(_ context.Context) ([]*project.Project, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*project.Project, 0, len(r.insertOrder))
	for _, pid := range r.insertOrder {
		if p, ok := r.byID[pid]; ok {
			out = append(out, cloneProject(p))
		}
	}
	return out, nil
}

// Save upserts. When p.ID is empty, mints a new one and populates it on
// the caller's struct so the caller can see the assigned id (mirroring
// SQLAlchemy's behaviour of populating the PK on flush).
func (r *ProjectRepo) Save(_ context.Context, p *project.Project) error {
	if err := p.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Uniqueness check: another project with the same name must not exist.
	if existingID, ok := r.idByName[p.Name]; ok && existingID != p.ID {
		return project.ErrDuplicate
	}

	if p.ID == "" {
		p.ID = id.New()
		r.insertOrder = append(r.insertOrder, p.ID)
	} else if old, ok := r.byID[p.ID]; ok {
		// Renamed? Drop the old name index.
		if old.Name != p.Name {
			delete(r.idByName, old.Name)
		}
	} else {
		// Caller-supplied ID for a fresh row.
		r.insertOrder = append(r.insertOrder, p.ID)
	}
	r.byID[p.ID] = cloneProject(p)
	r.idByName[p.Name] = p.ID
	return nil
}

func (r *ProjectRepo) Delete(_ context.Context, projectID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.byID[projectID]
	if !ok {
		return project.ErrNotFound
	}
	delete(r.byID, projectID)
	delete(r.idByName, p.Name)
	for i, q := range r.insertOrder {
		if q == projectID {
			r.insertOrder = append(r.insertOrder[:i], r.insertOrder[i+1:]...)
			break
		}
	}
	return nil
}

func cloneProject(p *project.Project) *project.Project {
	out := *p
	return &out
}

// ----- Scope rules -----------------------------------------------------

type ScopeRepo struct {
	mu      sync.RWMutex
	byID    map[string]*scope.StoredRule
	byProj  map[string][]string // projectID -> ruleIDs in insertion order
	uniqKey map[string]string   // projectID|pattern -> ruleID
}

func NewScopeRepo() *ScopeRepo {
	return &ScopeRepo{
		byID:    make(map[string]*scope.StoredRule),
		byProj:  make(map[string][]string),
		uniqKey: make(map[string]string),
	}
}

func (r *ScopeRepo) ListByProject(_ context.Context, projectID string) ([]scope.StoredRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.byProj[projectID]
	out := make([]scope.StoredRule, 0, len(ids))
	for _, rid := range ids {
		if sr, ok := r.byID[rid]; ok {
			out = append(out, *sr)
		}
	}
	return out, nil
}

func (r *ScopeRepo) Add(_ context.Context, sr *scope.StoredRule) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := sr.ProjectID + "|" + sr.Rule.Pattern
	if _, dup := r.uniqKey[key]; dup {
		return scope.ErrDuplicate
	}
	if sr.ID == "" {
		sr.ID = id.New()
	}
	stored := *sr
	r.byID[sr.ID] = &stored
	r.byProj[sr.ProjectID] = append(r.byProj[sr.ProjectID], sr.ID)
	r.uniqKey[key] = sr.ID
	return nil
}

func (r *ScopeRepo) Delete(_ context.Context, ruleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	sr, ok := r.byID[ruleID]
	if !ok {
		return scope.ErrNotFound
	}
	delete(r.byID, ruleID)
	delete(r.uniqKey, sr.ProjectID+"|"+sr.Rule.Pattern)
	ids := r.byProj[sr.ProjectID]
	for i, rid := range ids {
		if rid == ruleID {
			r.byProj[sr.ProjectID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	return nil
}

// ----- Runs ------------------------------------------------------------

type RunRepo struct {
	mu sync.RWMutex

	runsByID map[string]*run.Run
	runOrder map[string][]string // projectID -> runIDs in insertion order

	txByID  map[string]*run.ToolExecution
	txByRun map[string][]string // runID -> txIDs in insertion order
}

func NewRunRepo() *RunRepo {
	return &RunRepo{
		runsByID: make(map[string]*run.Run),
		runOrder: make(map[string][]string),
		txByID:   make(map[string]*run.ToolExecution),
		txByRun:  make(map[string][]string),
	}
}

func (r *RunRepo) Get(_ context.Context, runID string) (*run.Run, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	got, ok := r.runsByID[runID]
	if !ok {
		return nil, run.ErrNotFound
	}
	clone := *got
	return &clone, nil
}

func (r *RunRepo) ListByProject(_ context.Context, projectID string) ([]*run.Run, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.runOrder[projectID]
	// Insertion order is chronological (Save appends on create). Walk
	// it in reverse to produce newest-first without per-row timestamps.
	out := make([]*run.Run, 0, len(ids))
	for i := len(ids) - 1; i >= 0; i-- {
		if got, ok := r.runsByID[ids[i]]; ok {
			clone := *got
			out = append(out, &clone)
		}
	}
	return out, nil
}

func (r *RunRepo) Save(_ context.Context, ru *run.Run) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ru.ID == "" {
		ru.ID = id.New()
		r.runOrder[ru.ProjectID] = append(r.runOrder[ru.ProjectID], ru.ID)
	} else if _, ok := r.runsByID[ru.ID]; !ok {
		// Caller-supplied ID, treat as create.
		r.runOrder[ru.ProjectID] = append(r.runOrder[ru.ProjectID], ru.ID)
	}
	clone := *ru
	r.runsByID[ru.ID] = &clone
	return nil
}

func (r *RunRepo) Delete(_ context.Context, runID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ru, ok := r.runsByID[runID]
	if !ok {
		return run.ErrNotFound
	}
	delete(r.runsByID, runID)
	ids := r.runOrder[ru.ProjectID]
	for i, rid := range ids {
		if rid == runID {
			r.runOrder[ru.ProjectID] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	// Cascade tool executions.
	for _, txID := range r.txByRun[runID] {
		delete(r.txByID, txID)
	}
	delete(r.txByRun, runID)
	return nil
}

func (r *RunRepo) SaveToolExecution(_ context.Context, tx *run.ToolExecution) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.runsByID[tx.RunID]; !ok {
		return run.ErrNotFound
	}
	if tx.ID == "" {
		tx.ID = id.New()
		r.txByRun[tx.RunID] = append(r.txByRun[tx.RunID], tx.ID)
	} else if _, ok := r.txByID[tx.ID]; !ok {
		r.txByRun[tx.RunID] = append(r.txByRun[tx.RunID], tx.ID)
	}
	clone := *tx
	r.txByID[tx.ID] = &clone
	return nil
}

func (r *RunRepo) ListToolExecutions(_ context.Context, runID string) ([]*run.ToolExecution, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := r.txByRun[runID]
	out := make([]*run.ToolExecution, 0, len(ids))
	for _, txID := range ids {
		if tx, ok := r.txByID[txID]; ok {
			clone := *tx
			out = append(out, &clone)
		}
	}
	return out, nil
}

// Compile-time assertions that the in-memory types implement the domain
// repository interfaces. If a method signature drifts on either side
// this fails to build, which is precisely what we want.
var (
	_ project.Repository = (*ProjectRepo)(nil)
	_ scope.Repository   = (*ScopeRepo)(nil)
	_ run.Repository     = (*RunRepo)(nil)
)
