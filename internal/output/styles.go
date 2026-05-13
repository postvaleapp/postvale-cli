// Package output renders API responses to the terminal. The base
// styles + colour palette live here so every command uses the same
// look (amber accent, slate text, emerald/red verdict colours that
// match the web brand).
package output

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// Adaptive colours - Lipgloss picks the right side of the pair
// based on the terminal's background (light vs dark). Keeps things
// readable on both `iTerm light` and `Alacritty dark` setups.
var (
	colAmber       = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	colSlate       = lipgloss.AdaptiveColor{Light: "#475569", Dark: "#94A3B8"}
	colSlateDim    = lipgloss.AdaptiveColor{Light: "#94A3B8", Dark: "#64748B"}
	colSlateStrong = lipgloss.AdaptiveColor{Light: "#0F172A", Dark: "#F8FAFC"}
	colEmerald     = lipgloss.AdaptiveColor{Light: "#047857", Dark: "#34D399"}
	colAmberMid    = lipgloss.AdaptiveColor{Light: "#D97706", Dark: "#F59E0B"}
	colRed         = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	colBorder      = lipgloss.AdaptiveColor{Light: "#CBD5E1", Dark: "#334155"}
)

// Re-exported helpers so command code can compose its own styles
// without re-deriving the palette.
var (
	StyleHeader = lipgloss.NewStyle().
			Foreground(colAmber).
			Bold(true)

	StyleLabel = lipgloss.NewStyle().
			Foreground(colSlate)

	StyleStrong = lipgloss.NewStyle().
			Foreground(colSlateStrong).
			Bold(true)

	StyleDim = lipgloss.NewStyle().
			Foreground(colSlateDim)

	StyleOK = lipgloss.NewStyle().
		Foreground(colEmerald)

	StyleWarn = lipgloss.NewStyle().
			Foreground(colAmberMid)

	StyleFail = lipgloss.NewStyle().
			Foreground(colRed)

	StyleBox = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colBorder).
			Padding(0, 2)
)

// GradeStyle returns the colour for a given letter grade. Keeps the
// "A is emerald, F is red" mapping consistent across every renderer.
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

// VerdictStyle returns the colour for a Scam Check verdict.
func VerdictStyle(verdict string) lipgloss.Style {
	switch verdict {
	case "likely-safe":
		return StyleOK.Bold(true)
	case "suspicious":
		return StyleWarn.Bold(true)
	case "likely-scam":
		return StyleFail.Bold(true)
	default:
		return StyleDim
	}
}

// Disable strips colour codes globally. Used for --no-color or when
// stdout isn't a TTY. Call before any rendering.
func Disable() {
	lipgloss.SetColorProfile(termenv.Ascii)
}
