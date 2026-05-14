package tui

import (
	"net/url"
	"os/exec"
	"runtime"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
)

// TUI palette - mirrors the one in internal/output but tuned for
// terminal-fullscreen rendering (slightly more saturated, no
// border-foreground assumptions).
var (
	colAmber       = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	colSlate       = lipgloss.AdaptiveColor{Light: "#475569", Dark: "#94A3B8"}
	colSlateDim    = lipgloss.AdaptiveColor{Light: "#94A3B8", Dark: "#64748B"}
	colSlateStrong = lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#F8FAFC"}
	colEmerald     = lipgloss.AdaptiveColor{Light: "#047857", Dark: "#34D399"}
	colAmberMid    = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#F59E0B"}
	colRed         = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
)

var (
	StyleHeader = lipgloss.NewStyle().Foreground(colAmber).Bold(true)
	StyleLabel  = lipgloss.NewStyle().Foreground(colSlate)
	StyleStrong = lipgloss.NewStyle().Foreground(colSlateStrong).Bold(true)
	StyleDim    = lipgloss.NewStyle().Foreground(colSlateDim)
	StyleOK     = lipgloss.NewStyle().Foreground(colEmerald)
	StyleWarn   = lipgloss.NewStyle().Foreground(colAmberMid)
	StyleFail   = lipgloss.NewStyle().Foreground(colRed)
)

func styleLabel(s string) string {
	return StyleLabel.Width(16).Render(s)
}

// GradeStyle returns a style for a letter-grade pill. Mirrors the
// mapping used in internal/output so terminal output stays
// consistent across commands and TUI.
func GradeStyle(grade string) lipgloss.Style {
	switch grade {
	case "A+", "A":
		return StyleOK.Bold(true)
	case "B", "C":
		return StyleWarn.Bold(true)
	case "D", "F":
		return StyleFail.Bold(true)
	default:
		return StyleDim
	}
}

func tableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(colSlateDim).
		BorderBottom(true).
		Bold(true).
		Foreground(colAmber)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("#FFFFFF")).
		Background(colAmber).
		Bold(true)
	return s
}

// openURL shells out to the platform-native opener via exec.Command
// argv form (never a shell). Refuses non-http(s) schemes so a
// malicious --api response or rogue config can't push a file: /
// javascript: / vbscript: URL to xdg-open / rundll32 / open. Errors
// after the scheme check are swallowed - the TUI keeps running.
func openURL(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return
	}
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", rawURL).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		_ = exec.Command("xdg-open", rawURL).Start()
	}
}
