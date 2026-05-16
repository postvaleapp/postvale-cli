package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// VerifyPage is a wizard around `wd audit verify`. Text input
// for the JSONL export path, optional --fetch-anchor toggle, runs the
// binary in a subprocess + renders the captured output.

type verifyDoneMsg struct {
	stdout string
	stderr string
	err    error
	took   time.Duration
}

type VerifyPage struct {
	width  int
	height int

	path        textinput.Model
	fetchAnchor bool

	running bool
	last    *verifyDoneMsg
}

func newVerifyPage() VerifyPage {
	ti := textinput.New()
	ti.Placeholder = "/path/to/audit-chain.jsonl"
	ti.Prompt = "  ▸ "
	ti.CharLimit = 256
	ti.Focus()
	return VerifyPage{
		path:        ti,
		fetchAnchor: false,
	}
}

func (m VerifyPage) Init() tea.Cmd {
	return textinput.Blink
}

func (m VerifyPage) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.path.Width = m.width - 10
		return m, nil
	case verifyDoneMsg:
		m.running = false
		m.last = &msg
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+l":
			m.last = nil
			return m, nil
		case "ctrl+a":
			m.fetchAnchor = !m.fetchAnchor
			return m, nil
		case "enter":
			if m.running {
				return m, nil
			}
			val := strings.TrimSpace(m.path.Value())
			if val == "" {
				return m, nil
			}
			m.running = true
			return m, runVerifyCmd(val, m.fetchAnchor)
		}
	}
	var cmd tea.Cmd
	m.path, cmd = m.path.Update(msg)
	return m, cmd
}

func runVerifyCmd(path string, fetchAnchor bool) tea.Cmd {
	return func() tea.Msg {
		start := time.Now()
		bin, err := os.Executable()
		if err != nil {
			bin = os.Args[0]
		}
		args := []string{"audit", "verify", path}
		if fetchAnchor {
			args = append(args, "--fetch-anchor")
		}
		cmd := exec.Command(bin, args...)
		var stdoutB, stderrB bytes.Buffer
		cmd.Stdout = &stdoutB
		cmd.Stderr = &stderrB
		runErr := cmd.Run()
		return verifyDoneMsg{
			stdout: stdoutB.String(),
			stderr: stderrB.String(),
			err:    runErr,
			took:   time.Since(start),
		}
	}
}

func (m VerifyPage) View() string {
	var b strings.Builder
	b.WriteString("\n  ")
	b.WriteString(pageTitle("Verify audit chain", "independent re-check"))
	b.WriteString("\n\n")
	b.WriteString("  " + StyleDim.Render(
		"Re-computes the Merkle chain on a local JSONL export. Spec at",
	))
	b.WriteString("\n  " + StyleDim.Render(
		"https://wiredepth.com/docs/verify · No Postvale login required.",
	))
	b.WriteString("\n\n")

	b.WriteString("  " + StyleLabel.Render("FILE"))
	b.WriteString("\n")
	b.WriteString(m.path.View())
	b.WriteString("\n\n")

	anchor := "off"
	if m.fetchAnchor {
		anchor = StyleOK.Render("on")
	} else {
		anchor = StyleDim.Render("off")
	}
	b.WriteString("  " + StyleLabel.Render("FETCH LIVE ANCHOR") + "  " + anchor)
	b.WriteString("\n  " + StyleDim.Render(
		"Ctrl-A toggles. When on, the verifier asks /api/v1/audit/anchors",
	))
	b.WriteString("\n  " + StyleDim.Render(
		"for the current chain head and asserts your export's tail matches.",
	))
	b.WriteString("\n\n")

	if m.running {
		b.WriteString("  " + StyleWarn.Render("Verifying..."))
		return b.String()
	}

	if m.last != nil {
		dur := m.last.took.Round(time.Millisecond)
		if m.last.err != nil && m.last.stdout == "" && m.last.stderr == "" {
			b.WriteString("  " + StyleFail.Render("Could not run verifier:") + "\n")
			b.WriteString("  " + StyleDim.Render(m.last.err.Error()))
		} else {
			head := "  " + StyleOK.Render("PASS")
			if m.last.err != nil {
				head = "  " + StyleFail.Render("FAIL")
			}
			b.WriteString(head + "  " + StyleDim.Render(fmt.Sprintf("(%s)", dur)))
			b.WriteString("\n\n")
			out := strings.TrimRight(m.last.stdout, "\n")
			for _, line := range strings.Split(out, "\n") {
				b.WriteString("  " + line + "\n")
			}
			if m.last.stderr != "" {
				b.WriteString("\n  " + StyleLabel.Render("STDERR") + "\n")
				for _, line := range strings.Split(strings.TrimRight(m.last.stderr, "\n"), "\n") {
					b.WriteString("  " + StyleDim.Render(line) + "\n")
				}
			}
		}
		b.WriteString("\n  " + StyleDim.Render("Ctrl-L clears  ·  Enter re-verify"))
	} else {
		b.WriteString("  " + StyleDim.Render("Enter to run  ·  Tab to focus sidebar"))
	}

	return b.String()
}
