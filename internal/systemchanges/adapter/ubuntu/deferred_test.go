package ubuntu

import (
	"os"
	"path"
	"testing"

	"github.com/albertloky/SBXR/internal/systemchanges"
)

func TestDeferredReplacementRecoveryChoosesJournaledGeneration(t *testing.T) {
	for _, test := range []struct {
		name      string
		journal   []journalEntry
		wantState string
	}{
		{name: "restore old generation before final checkpoint", journal: []journalEntry{{Checkpoint: systemchanges.StepCompleted}}, wantState: "old"},
		{name: "keep new generation after final checkpoint", journal: []journalEntry{{Checkpoint: systemchanges.StepCompleted}, {Checkpoint: systemchanges.StateFinalized, State: &systemchanges.StateTransactionBinding{}}}, wantState: "new"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootPath := t.TempDir()
			for _, directory := range []string{"change/prepared", "change/prepared.previous"} {
				if err := os.MkdirAll(path.Join(rootPath, directory), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path.Join(rootPath, "change/prepared/state.json"), []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path.Join(rootPath, "change/prepared.previous/state.json"), []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path.Join(rootPath, "change/manifest.json"), []byte("new-manifest"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path.Join(rootPath, "change/manifest.previous"), []byte("old-manifest"), 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := reconcileDeferredReplacement(root, "change", test.journal); err != nil {
				t.Fatal(err)
			}
			got, err := root.ReadFile("change/prepared/state.json")
			if err != nil || string(got) != test.wantState || pathExists(root, "change/prepared.previous") || pathExists(root, "change/manifest.previous") {
				t.Fatalf("generation = %q, err=%v", got, err)
			}
		})
	}
}
