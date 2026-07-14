package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/JaydenCJ/corsdoctor/internal/cors"
	"github.com/JaydenCJ/corsdoctor/internal/version"
)

// envelope is the stable machine-readable report. schema_version only
// changes when a field is renamed or removed, never for additions.
type envelope struct {
	SchemaVersion int    `json:"schema_version"`
	Tool          string `json:"tool"`
	Version       string `json:"version"`
	ExitCode      int    `json:"exit_code"`
	*cors.Verdict
}

// JSON writes the verdict as indented JSON with a fixed envelope.
func JSON(w io.Writer, v *cors.Verdict, exitCode int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(envelope{
		SchemaVersion: 1,
		Tool:          "corsdoctor",
		Version:       version.Version,
		ExitCode:      exitCode,
		Verdict:       v,
	}); err != nil {
		return fmt.Errorf("encoding JSON report: %v", err)
	}
	return nil
}
