package dbprojects

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	gitutils "github.com/adedayo/checkmate-badger-project-manager/pkg/git"
	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	coregitutils "github.com/adedayo/checkmate-core/pkg/git"
	projects "github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/adedayo/checkmate-core/pkg/util"
	"github.com/dgraph-io/badger/v3"
	"gopkg.in/yaml.v3"
)

var (
	projectSummaryFile   = "project-summary.yaml"
	defaultCodeDirPrefix = "code"
)

func NewDBProjectManager(checkMateBaseDir string) (projects.ProjectManager, error) {

	pm := dbProjectManager{
		baseDir:              checkMateBaseDir,
		projectsLocation:     path.Join(checkMateBaseDir, "projects_db"),
		codeBaseDir:          path.Join(checkMateBaseDir, defaultCodeDirPrefix),
		projectTable:         "proj_",
		workspaceTable:       "works_",
		scanDiagnosticsTable: "scans_",
		scanPolicyTable:      "pol_",
		scanSummaryTable:     "ssum_",
		gitServiceTable:      "gits_",
		initTable:            "init_",
	}

	//attempt to create the project location if it doesn't exist
	os.MkdirAll(pm.projectsLocation, 0755)

	//attempt to manage memory by setting WithNum...
	opts := badger.DefaultOptions(pm.projectsLocation) //.WithNumMemtables(1).WithNumLevelZeroTables(1).WithNumLevelZeroTablesStall(5)

	//clean up lock on the DB if previous crash
	lockFile := path.Join(opts.Dir, "LOCK")
	_ = os.Remove(lockFile)

	db, err := badger.Open(opts)
	if err != nil {
		return pm, err
	}
	pm.db = db

	//import data from the YAML-based config if it exists
	importYAMLData(&pm)

	return pm, nil
}

func importYAMLData(pm *dbProjectManager) {
	err := pm.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(toKey(pm.initTable))
		return err
	})

	if errors.Is(err, badger.ErrKeyNotFound) {
		//create table
		pm.db.Update(func(txn *badger.Txn) error {
			return txn.Set(toKey(pm.initTable), []byte{})
		})

		//import data
		pm_ := projects.MakeSimpleProjectManager(pm.baseDir)

		if wss, err := pm_.GetWorkspaces(); err == nil {
			pm.SaveWorkspaces(wss)
		}

		for _, ps := range searchFileBasedProjects(pm_) {
			if proj, err := pm_.GetProject(ps.ID); err == nil {
				//We've now brought these two fields into ProjectSummary
				ps.ScanIDs = proj.ScanIDs
				ps.ScanPolicy = proj.ScanPolicy
			}
			ps.ScoreTrend = projects.LoadHistoricalScores(ps.ID, pm_)
			ps.LastScanSummary = loadLastScanSummary(ps.ID, pm_)
			pm.SaveProjectSummary(ps)

			for _, scanID := range ps.ScanIDs {
				if scanSummary, err := pm_.GetScanResultSummary(ps.ID, scanID); err == nil {
					pm.saveScanSummary(ps.ID, scanID, &scanSummary)
				}

				if pol, err := pm_.GetScanConfig(ps.ID, scanID); err == nil {
					pm.saveScanPolicy(ps.ID, scanID, pol)
				}

				if diagnostics, err := pm_.GetScanResults(ps.ID, scanID); err == nil {
					pm.db.Update(func(txn *badger.Txn) error {
						data, err := json.Marshal(diagnostics)
						if err != nil {
							return err
						}
						return txn.Set(toTableKey(pm.scanDiagnosticsTable, ps.ID, scanID), data)
					})
				}

			}
		}

	}
}

func loadLastScanSummary(projID string, pm projects.ProjectManager) (summary projects.ScanSummary) {
	if project, err := pm.GetProject(projID); err == nil {
		if len(project.ScanIDs) > 0 {
			scanID := project.ScanIDs[len(project.ScanIDs)-1]
			if s, err := pm.GetScanResultSummary(projID, scanID); err == nil {
				summary = s
			}
		}
	}
	return
}

func searchFileBasedProjects(pm projects.ProjectManager) (summaries []*projects.ProjectSummary) {

	if dirs, err := os.ReadDir(pm.GetProjectLocation("")); err == nil {
		for _, dir := range dirs {
			if dir.IsDir() {
				var proj projects.ProjectSummary
				data, err := os.ReadFile(path.Join(pm.GetProjectLocation(""), dir.Name(), projectSummaryFile))
				if err == nil {
					if err = yaml.Unmarshal(data, &proj); err == nil {
						summaries = append(summaries, &proj)
					}
				}
			}
		}
	}

	return
}

type dbProjectManager struct {
	baseDir, projectsLocation, codeBaseDir                        string
	db                                                            *badger.DB
	gitConfigManager                                              coregitutils.GitConfigManager
	projectTable, workspaceTable, scanDiagnosticsTable            string
	scanPolicyTable, scanSummaryTable, gitServiceTable, initTable string
}

// DeleteProject implements ProjectManager
func (pm dbProjectManager) DeleteProject(id string) error {
	proj, err := pm.GetProjectSummary(id)
	if err != nil {
		return err
	}

	//delete project
	pm.deleteProjectSummary(id)
	//remove it from workspaces
	if ws, err := pm.GetWorkspaces(); err == nil {
		ws.RemoveProjectSummary(proj, pm)
	}
	//delete checked out code
	for _, r := range proj.Repositories {
		if r.IsGit() {
			os.RemoveAll(r.GetCodeLocation(pm, id))
		}
	}
	return nil
}

// GetGitConfigManager implements ProjectManager
func (pm dbProjectManager) GetGitConfigManager() (coregitutils.GitConfigManager, error) {

	if pm.gitConfigManager == nil {
		cm, e := gitutils.NewDBGitConfigManager(pm.baseDir)
		pm.gitConfigManager = cm
		return cm, e
	}

	return pm.gitConfigManager, nil
}

func (pm dbProjectManager) Close() error {
	if pm.db != nil {
		return pm.db.Close()
	}
	return errors.New("Attempting to close uninitialised DB")
}

// CreateProject implements ProjectManager
func (pm dbProjectManager) CreateProject(projectDescription projects.ProjectDescription) (*projects.Project, error) {
	project := projects.ProjectFromDescription(projectDescription)

	summary := &projects.ProjectSummary{
		ID:                     project.ID,
		Name:                   project.Name,
		Workspace:              project.Workspace,
		CreationDate:           time.Now(),
		Repositories:           project.Repositories,
		ScanAndCommitHistories: make(map[string]map[string]projects.RepositoryHistory),
	}

	data, err := json.Marshal(summary)

	if err != nil {
		return &project, err
	}

	err = pm.db.Update(func(txn *badger.Txn) error {
		return txn.Set(pm.toProjectKey(project.ID), data)
	})
	return &project, err
}

func (pm dbProjectManager) toProjectKey(projID string) []byte {
	return []byte(fmt.Sprintf("%s%s", pm.projectTable, projID))
}

// GetBaseDir implements ProjectManager
func (pm dbProjectManager) GetBaseDir() string {
	return pm.baseDir
}

// GetCodeBaseDir implements ProjectManager
func (pm dbProjectManager) GetCodeBaseDir() string {
	return pm.codeBaseDir
}

// GetCodeContext implements ProjectManager
func (pm dbProjectManager) GetCodeContext(cnt common.CodeContext) string {
	return projects.GetCodeContext(pm.codeBaseDir, cnt)
}

// GetIssues implements ProjectManager
func (pm dbProjectManager) GetIssues(paginated projects.PaginatedIssueSearch) (*projects.PagedResult, error) {
	results, err := pm.GetScanResults(paginated.ProjectID, paginated.ScanID)
	if err != nil {
		return nil, err
	}

	return projects.PageIssues(paginated, results), nil
}

// GetProject implements ProjectManager
func (pm dbProjectManager) GetProject(id string) (projects.Project, error) {
	var proj projects.Project

	pSum, err := pm.GetProjectSummary(id)
	if err != nil {
		return proj, err
	}
	return pSum.ToProject(), nil
}

// GetProjectLocation implements ProjectManager
func (pm dbProjectManager) GetProjectLocation(projID string) string {
	return path.Join(pm.projectsLocation, projID)
}

// GetProjectSummary implements ProjectManager
func (pm dbProjectManager) GetProjectSummary(projectID string) (*projects.ProjectSummary, error) {
	var pSum projects.ProjectSummary
	err := pm.db.View(func(txn *badger.Txn) error {
		item, e := txn.Get(pm.toProjectKey(projectID))
		if e == nil {
			return item.Value(func(val []byte) error {
				return json.Unmarshal(val, &pSum)
			})
		}
		return e
	})
	return &pSum, err
}

func (pm dbProjectManager) deleteProjectSummary(projectID string) error {
	return pm.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(pm.toProjectKey(projectID))
	})
}

// GetScanConfig implements ProjectManager
func (pm dbProjectManager) GetScanConfig(projectID string, scanID string) (*projects.ScanPolicy, error) {

	var pol projects.ScanPolicy
	err := pm.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(pm.scanPolicyTable)
		desiredKey := toTableKey(pm.scanPolicyTable, projectID, scanID)

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			key := item.Key()

			if bytes.Equal(desiredKey, key) {
				return item.Value(func(val []byte) error {
					return yaml.Unmarshal(val, &pol)
				})

			}
		}
		return fmt.Errorf("Could not find Policy for Project %s and ScanID %s", projectID, scanID)
	})

	return &pol, err
}

// GetScanResultSummary implements ProjectManager
func (pm dbProjectManager) GetScanResultSummary(projectID string, scanID string) (projects.ScanSummary, error) {
	var scanSummary projects.ScanSummary
	err := pm.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(toTableKey(pm.scanSummaryTable, projectID, scanID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &scanSummary)
		})
	})

	return scanSummary, err
}

// GetScanResults implements ProjectManager
func (pm dbProjectManager) GetScanResults(projectID string, scanID string) ([]*diagnostics.SecurityDiagnostic, error) {

	diagnostics := []*diagnostics.SecurityDiagnostic{}
	err := pm.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(toTableKey(pm.scanDiagnosticsTable, projectID, scanID))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &diagnostics)
		})
	})
	return diagnostics, err

}

// GetWorkspaces implements ProjectManager
func (pm dbProjectManager) GetWorkspaces() (*projects.Workspace, error) {
	wss := projects.Workspace{
		Details: make(map[string]*projects.WorkspaceDetail),
	}
	err := pm.db.View(func(txn *badger.Txn) error {
		item, rerr := txn.Get(toKey(pm.workspaceTable))
		if rerr != nil {
			return rerr
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &wss)
		})
	})

	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		//create a new workspace, if it didn't exist
		err = pm.SaveWorkspaces(&wss)
	}

	return &wss, err
}

// ListProjectSummaries implements ProjectManager
func (pm dbProjectManager) ListProjectSummaries() []*projects.ProjectSummary {
	pSums := []*projects.ProjectSummary{}
	pm.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(pm.projectTable)

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			item.Value(func(val []byte) error {
				var pSum projects.ProjectSummary
				err := json.Unmarshal(val, &pSum)
				if err == nil {
					pSums = append(pSums, &pSum)
				}
				return err
			})
		}
		return nil
	})
	sorted := make(projects.ProjectSummarySlice, 0)
	sorted = append(sorted, pSums...)
	sort.Sort(sorted)

	return sorted
}

// RemediateIssue implements ProjectManager
func (pm dbProjectManager) RemediateIssue(exclude diagnostics.ExcludeRequirement) diagnostics.PolicyUpdateResult {
	return projects.UpdatePolicy(exclude, pm)
}

// RunScan implements ProjectManager
func (pm dbProjectManager) RunScan(ctx context.Context, projectID string, scanPolicy projects.ScanPolicy, scanner projects.SecurityScanner, scanIDCallback func(string), progressMonitor func(diagnostics.Progress), summariser projects.ScanSummariser, wsSummariser projects.WorkspaceSummariser, consumers ...diagnostics.SecurityDiagnosticsConsumer) {
	scanID := pm.createScan(projectID, scanPolicy)
	scanIDCallback(scanID)
	ddc := newDBDiagnosticConsumer(projectID, scanID, &pm)
	consumers = append(consumers, ddc)
	scannedCommits := projects.RetrieveCommitsToBeScanned(projectID, scanID, pm, progressMonitor)
	//set "being-scanned" flag
	summary, err := pm.GetProjectSummary(projectID)
	if err == nil {
		summary.IsBeingScanned = true
		pm.SaveProjectSummary(summary)
	} else {
		return
	}

	progressMonitor(diagnostics.Progress{
		ProjectID:   projectID,
		ScanID:      scanID,
		Position:    0,
		Total:       1,
		CurrentFile: fmt.Sprintf("starting scan ..."),
	})

	scanner.Scan(ctx, projectID, scanID, pm, progressMonitor, consumers...)
	scanEndTime := time.Now()
	ddc.close()
	if scanSummary, err := pm.summariseScanResults(projectID, scanID, summariser); err == nil {
		if proj, err := pm.updateScanHistory(projectID, scanID, scanEndTime, scanSummary, scannedCommits); err == nil {
			if wsSummariser != nil {
				if wss, err := wsSummariser(pm, []string{proj.Workspace}); err == nil {
					go pm.SaveWorkspaces(wss)
				}
			}
		}
	}
}

func (pm dbProjectManager) summariseScanResults(projectID, scanID string, summariser func(projectID, scanID string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary) (*projects.ScanSummary, error) {

	results, err := pm.GetScanResults(projectID, scanID)
	if err != nil {
		return nil, err
	}
	scanSummary := summariser(projectID, scanID, results)
	return scanSummary, pm.saveScanSummary(projectID, scanID, scanSummary)
}

func (pm dbProjectManager) saveScanSummary(projectID, scanID string, scanSummary *projects.ScanSummary) error {

	data, err := json.Marshal(scanSummary)
	if err != nil {
		return err
	}
	return pm.db.Update(func(txn *badger.Txn) error {
		return txn.Set(toTableKey(pm.scanSummaryTable, projectID, scanID), data)
	})

}

func (pm dbProjectManager) updateScanHistory(projectID, scanID string, scanEndTime time.Time, scanSummary *projects.ScanSummary, scannedCommits map[string]projects.ScannedCommit) (*projects.ProjectSummary, error) {
	pSum, err := pm.GetProjectSummary(projectID)
	if err != nil {
		return pSum, err
	}
	projects.UpdateScanHistoryAtEndOfScan(pSum, scannedCommits, scanID, scanSummary, pm)
	return pSum, pm.SaveProjectSummary(pSum)
}

func (pm dbProjectManager) createScan(projectID string, scanPolicy projects.ScanPolicy) (scanID string) {
	proj, err := pm.GetProjectSummary(projectID)
	if err != nil {
		//project does not exist
		return
	}

	scanID = util.NewRandomUUID().String()
	proj.ScanIDs = append(proj.ScanIDs, scanID)
	proj.LastScanID = scanID
	proj.LastModification = time.Now()
	proj.IsBeingScanned = true
	pm.SaveProjectSummary(proj)

	policy := projects.ScanPolicy{
		ID:     scanID,
		Policy: scanPolicy.Policy,
	}

	if err := pm.saveScanPolicy(projectID, scanID, &policy); err != nil {
		return ""
	}
	return
}

func (pm dbProjectManager) saveModifiedProject(proj *projects.ProjectSummary) (*projects.Project, error) {
	proj.LastModification = time.Now()
	p := proj.ToProject()
	return &p, pm.SaveProjectSummary(proj)
}

// SaveProjectSummary implements ProjectManager
func (pm dbProjectManager) SaveProjectSummary(proj *projects.ProjectSummary) error {
	return pm.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(proj)
		if err != nil {
			return err
		}
		return txn.Set(toKey(pm.projectTable, proj.ID), data)
	})
}

func (pm dbProjectManager) saveScanPolicy(projID, scanID string, policy *projects.ScanPolicy) error {

	data, err := yaml.Marshal(policy)
	if err != nil {
		return err
	}

	return pm.db.Update(func(txn *badger.Txn) error {
		return txn.Set(toTableKey(pm.scanPolicyTable, projID, scanID), data)
	})

}

// SaveWorkspaces implements ProjectManager
func (pm dbProjectManager) SaveWorkspaces(ws *projects.Workspace) error {
	return pm.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(ws)
		if err != nil {
			return err
		}
		return txn.Set(toKey(pm.workspaceTable), data)
	})
}

// UpdateProject implements ProjectManager
func (pm dbProjectManager) UpdateProject(projectID string, projectDescription projects.ProjectDescription, wsSummariser projects.WorkspaceSummariser) (*projects.Project, error) {
	proj, err := pm.GetProjectSummary(projectID)

	if err != nil {
		return nil, err
	}
	if proj.ID == projectID {
		//found project, update
		proj.Name = projectDescription.Name
		wspaces := []string{proj.Workspace}
		wsChange := false
		if proj.Workspace != projectDescription.Workspace {
			//project workspace changing
			wsChange = true
			wspaces = append(wspaces, projectDescription.Workspace)
			proj.Workspace = projectDescription.Workspace
		}
		proj.Repositories = projectDescription.Repositories
		policy := projects.ScanPolicy{
			ID:           util.NewRandomUUID().String(),
			Policy:       projectDescription.ScanPolicy.Policy,
			Config:       projectDescription.ScanPolicy.Config,
			PolicyString: projectDescription.ScanPolicy.PolicyString,
		}
		proj.ScanPolicy = policy
		if wsChange && wsSummariser != nil {
			wss, err := wsSummariser(pm, wspaces)
			if err == nil {
				go pm.SaveWorkspaces(wss)
			} else {
				log.Printf("UpdateProject: %v", err)
			}
		}
		return pm.saveModifiedProject(proj)
	}
	//project not found, create one with a new ID
	return pm.CreateProject(projectDescription)

}

type dbDiagnosticConsumer struct {
	db          *badger.DB
	table       []byte
	diagnostics []*diagnostics.SecurityDiagnostic
}

func (ddc *dbDiagnosticConsumer) ReceiveDiagnostic(diag *diagnostics.SecurityDiagnostic) {
	ddc.diagnostics = append(ddc.diagnostics, diag)
}

func (ddc *dbDiagnosticConsumer) close() error {
	//write the collected diagnostics to db
	return ddc.db.Update(func(txn *badger.Txn) error {
		data, err := json.Marshal(ddc.diagnostics)
		if err != nil {
			return err
		}
		return txn.Set(ddc.table, data)
	})
}

func newDBDiagnosticConsumer(projectID, scanID string, pm *dbProjectManager) *dbDiagnosticConsumer {
	ddc := dbDiagnosticConsumer{
		db:          pm.db,
		table:       toTableKey(pm.scanDiagnosticsTable, projectID, scanID),
		diagnostics: []*diagnostics.SecurityDiagnostic{},
	}

	return &ddc
}

func toTableKey(prefix, projectID, scanID string) []byte {
	return []byte(fmt.Sprintf("%s%s%s", prefix, projectID, scanID))
}

func toKey(keys ...string) []byte {
	return []byte(strings.Join(keys, ""))
}
