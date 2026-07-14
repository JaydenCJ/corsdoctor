// Package report renders a cors.Verdict for humans (terminal text) and
// machines (stable JSON).
package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/corsdoctor/internal/cors"
)

// marks for step statuses.
var marks = map[cors.StepStatus]string{
	cors.StatusPass: "✓",
	cors.StatusFail: "✗",
	cors.StatusSkip: "–",
}

// Text renders the full human-readable diagnosis.
func Text(w io.Writer, v *cors.Verdict) {
	fmt.Fprintf(w, "corsdoctor — %s %s\n", v.Request.Method, v.Request.URL)
	fmt.Fprintf(w, "  origin       %s\n", v.Origin)
	fmt.Fprintf(w, "  credentials  %s\n", credentialsWord(v.Request.Credentials))
	fmt.Fprintf(w, "  class        %s\n", classLine(v))

	if v.Outcome == cors.OutcomeNotCORS {
		fmt.Fprintf(w, "\nverdict  NOT A CORS REQUEST\n  %s\n", v.Summary)
		renderNotes(w, v)
		return
	}

	renderClassification(w, v)
	renderSteps(w, v)
	renderVerdict(w, v)
	renderNotes(w, v)
}

func credentialsWord(c bool) string {
	if c {
		return "include (cookies / Authorization sent)"
	}
	return "omit"
}

func classLine(v *cors.Verdict) string {
	if v.Outcome == cors.OutcomeNotCORS {
		return "same-origin — CORS does not apply"
	}
	if v.Classification.PreflightRequired {
		return "cross-origin → preflight required"
	}
	return "cross-origin → no preflight needed (CORS-safelisted request)"
}

// renderClassification prints why (or why not) a preflight is required —
// per header, with the exact safelist rule that fired.
func renderClassification(w io.Writer, v *cors.Verdict) {
	cls := v.Classification
	fmt.Fprintf(w, "\nrequest classification\n")
	if cls.MethodSafelisted {
		fmt.Fprintf(w, "  ✓ method %s is CORS-safelisted\n", cls.Method)
	} else {
		fmt.Fprintf(w, "  ✗ method %s is not CORS-safelisted (GET, HEAD, POST)\n", cls.Method)
	}
	for _, h := range cls.Headers {
		name := strings.ToLower(h.Name)
		switch {
		case h.Forbidden:
			fmt.Fprintf(w, "  · %s — browser-owned, ignored\n", name)
		case h.Safelisted:
			fmt.Fprintf(w, "  ✓ %s — safelisted\n", nameAndValue(name, h.Value))
		default:
			fmt.Fprintf(w, "  ✗ %s — %s\n", nameAndValue(name, h.Value), h.Reason)
		}
	}
	if cls.PreflightRequired {
		fmt.Fprint(w, "  → the browser sends OPTIONS first")
		if len(cls.UnsafeHeaderNames) > 0 {
			fmt.Fprintf(w, " with Access-Control-Request-Headers: %s", strings.Join(cls.UnsafeHeaderNames, ", "))
		}
		fmt.Fprintln(w)
	}
}

// nameAndValue renders "name: value", truncating pathological values and
// omitting the colon for reconstructed headers with no known value.
func nameAndValue(name, value string) string {
	if value == "" {
		return name
	}
	if len(value) > 60 {
		value = value[:57] + "..."
	}
	return name + ": " + value
}

// renderSteps prints the algorithm trace, grouped by phase.
func renderSteps(w io.Writer, v *cors.Verdict) {
	phase := ""
	for _, s := range v.Steps {
		if s.Phase != phase {
			phase = s.Phase
			label := map[string]string{
				"preflight": "preflight response",
				"response":  "actual response",
			}[phase]
			fmt.Fprintf(w, "\n%s\n", label)
		}
		fmt.Fprintf(w, "  %s %s\n", marks[s.Status], s.Title)
		if s.Detail != "" {
			fmt.Fprintf(w, "      %s\n", s.Detail)
		}
		if s.Status == cors.StatusFail && s.Ref != "" {
			fmt.Fprintf(w, "      ref: %s\n", s.Ref)
		}
	}
}

func renderVerdict(w io.Writer, v *cors.Verdict) {
	fmt.Fprintln(w)
	switch v.Outcome {
	case cors.OutcomeAllowed:
		fmt.Fprintf(w, "verdict  ALLOWED\n  %s\n", v.Summary)
		if len(v.ExposedHeaders) > 0 {
			fmt.Fprintf(w, "  JavaScript can read these response headers: %s\n", strings.Join(v.ExposedHeaders, ", "))
		}
	case cors.OutcomeBlocked:
		fmt.Fprintf(w, "verdict  BLOCKED at %s\n  %s\n", v.Failed.ID, v.Failed.Detail)
		if v.BrowserMessage != "" {
			fmt.Fprintf(w, "\nbrowser console (Chrome-style)\n  %s\n", v.BrowserMessage)
		}
	case cors.OutcomeIncomplete:
		fmt.Fprintf(w, "verdict  INCOMPLETE\n  %s\n", v.Summary)
	case cors.OutcomeAdvisory:
		fmt.Fprintf(w, "verdict  ADVISORY\n  %s\n", v.Summary)
	}
	if len(v.Requirements) > 0 {
		fmt.Fprintf(w, "\nserver requirements\n")
		for _, r := range v.Requirements {
			fmt.Fprintf(w, "  • %s\n", r)
		}
	}
	if len(v.Fixes) > 0 {
		fmt.Fprintf(w, "\nfix\n")
		for _, f := range v.Fixes {
			fmt.Fprintf(w, "  • %s\n", f)
		}
	}
}

func renderNotes(w io.Writer, v *cors.Verdict) {
	if len(v.Warnings) > 0 {
		fmt.Fprintf(w, "\nwarnings\n")
		for _, s := range v.Warnings {
			fmt.Fprintf(w, "  ! %s\n", s)
		}
	}
	if len(v.Notes) > 0 {
		fmt.Fprintf(w, "\nnotes\n")
		for _, n := range v.Notes {
			fmt.Fprintf(w, "  · %s\n", n)
		}
	}
}
