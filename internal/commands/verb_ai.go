// `wd ai` verb group - AI-assisted runbook / draft generation.
// Phase 1 wires the abuse-report draft endpoint that ships on
// the webapp. Future v2.2 additions: `wd ai brief`, `wd ai
// runbook <finding-id>`, `wd ai chat` (REPL).
package commands

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/WiredepthHQ/cli/internal/auth"
	"github.com/WiredepthHQ/cli/internal/output"
)

func newAiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI-assisted runbooks + drafts (Pro+)",
		Long: `AI-assisted operator surfaces. Phase 1 ships the abuse-
report draft generator; v2.2 will add brief / runbook / explain /
chat subcommands matching the webapp surfaces.

Subcommands:
  wd ai abuse-draft   Draft an abuse-report email for a brand-
                      impersonation / phishing / lookalike finding`,
	}
	cmd.AddCommand(newAiAbuseDraftCommand())
	return cmd
}

type abuseDraftRequest struct {
	Kind             string   `json:"kind"`
	Recipient        string   `json:"recipient"`
	OwnApex          string   `json:"ownApex"`
	AbusingResource  string   `json:"abusingResource"`
	FirstSeenAt      string   `json:"firstSeenAt"`
	SuggestedContact string   `json:"suggestedContact,omitempty"`
	ContextLines     []string `json:"contextLines,omitempty"`
}

type abuseDraftResponse struct {
	ToLine              string   `json:"toLine"`
	SubjectLine         string   `json:"subjectLine"`
	BodyText            string   `json:"bodyText"`
	EvidenceBullets     []string `json:"evidenceBullets"`
	Confidence          string   `json:"confidence"`
	ConfidenceRationale string   `json:"confidenceRationale"`
}

func newAiAbuseDraftCommand() *cobra.Command {
	var (
		kind             string
		recipient        string
		ownApex          string
		abusingResource  string
		firstSeenAt      string
		suggestedContact string
		contextStr       string
	)
	cmd := &cobra.Command{
		Use:   "abuse-draft",
		Short: "Generate an abuse-report email draft",
		Long: `Generate an abuse-report email draft for a brand-
impersonation / phishing / lookalike / leak-mention / malicious-
redirect finding. The output is reviewed + sent by the operator;
WireDepth never sends anything outbound.

Required flags:
  --kind         finding kind (see list below)
  --recipient    bucket (registrar | hosting | cdn | email-provider | mail-blocklist)
  --apex         your own apex (the brand being impersonated)
  --resource     the abusing resource (domain / URL / IP)
  --first-seen   ISO-8601 timestamp or YYYY-MM-DD date

Kinds:
  brand-lookalike-domain   typosquat / homoglyph registered domain
  brand-lookalike-cert     CT-log lookalike cert issuance
  phishing-kit-detected    favicon/title/form fingerprint match
  credential-leak-mention  leak-site mention of @your-apex addresses
  malicious-redirect       open-redirect / spam-relay abuse of your domain

Pro tier required; gated server-side. AI requests are rate-limited
at 20/hour per IP.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			g := Globals()
			configureOutput(cmd.OutOrStdout())

			token := g.Token
			if token == "" {
				t, err := auth.Load()
				if err != nil {
					if errors.Is(err, auth.ErrNotLoggedIn) {
						return fmt.Errorf(
							"not signed in - run `wd auth login` first",
						)
					}
					return err
				}
				token = t
			}

			req := abuseDraftRequest{
				Kind:             strings.TrimSpace(kind),
				Recipient:        strings.TrimSpace(recipient),
				OwnApex:          strings.TrimSpace(ownApex),
				AbusingResource:  strings.TrimSpace(abusingResource),
				FirstSeenAt:      strings.TrimSpace(firstSeenAt),
				SuggestedContact: strings.TrimSpace(suggestedContact),
			}
			if contextStr != "" {
				for _, l := range strings.Split(contextStr, "\n") {
					if t := strings.TrimSpace(l); t != "" {
						req.ContextLines = append(req.ContextLines, t)
					}
				}
			}

			if req.Kind == "" || req.Recipient == "" || req.OwnApex == "" ||
				req.AbusingResource == "" || req.FirstSeenAt == "" {
				return fmt.Errorf(
					"required flags: --kind --recipient --apex --resource --first-seen",
				)
			}

			timeout := time.Duration(g.Timeout) * time.Second
			if g.Timeout <= 0 {
				timeout = 30 * time.Second
			}
			body, err := postJSON(
				g.APIBase+"/api/v1/ai/abuse-draft",
				token,
				timeout,
				req,
			)
			if err != nil {
				return fmt.Errorf("abuse-draft: %w", err)
			}
			var draft abuseDraftResponse
			if err := json.Unmarshal(body, &draft); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}

			if g.JSON {
				return output.EmitJSON(cmd.OutOrStdout(), draft)
			}
			renderAbuseDraft(cmd, draft)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "finding kind (see --help for values)")
	cmd.Flags().StringVar(&recipient, "recipient", "", "recipient bucket")
	cmd.Flags().StringVar(&ownApex, "apex", "", "your own apex (the impersonated brand)")
	cmd.Flags().StringVar(&abusingResource, "resource", "", "the abusing resource (domain/URL/IP)")
	cmd.Flags().StringVar(&firstSeenAt, "first-seen", time.Now().UTC().Format("2006-01-02"), "first-seen ISO-8601 or YYYY-MM-DD")
	cmd.Flags().StringVar(&suggestedContact, "contact", "", "suggested abuse-contact email")
	cmd.Flags().StringVar(&contextStr, "context", "", "extra context lines (newline-separated)")
	return cmd
}

func renderAbuseDraft(cmd *cobra.Command, draft abuseDraftResponse) {
	w := cmd.OutOrStdout()
	confTone := output.StyleDim
	switch draft.Confidence {
	case "high":
		confTone = output.StyleOK
	case "medium":
		confTone = output.StyleWarn
	}

	fmt.Fprintf(w, "%s %s %s\n",
		output.StyleDim.Render(">_"),
		output.StyleStrong.Render("ABUSE DRAFT"),
		confTone.Render("("+draft.Confidence+" confidence)"),
	)
	fmt.Fprintln(w, output.StyleDim.Render("why: "+draft.ConfidenceRationale))
	fmt.Fprintln(w)
	fmt.Fprintln(w, output.StyleDim.Render("To:      ")+draft.ToLine)
	fmt.Fprintln(w, output.StyleDim.Render("Subject: ")+draft.SubjectLine)
	fmt.Fprintln(w)
	fmt.Fprintln(w, output.StyleDim.Render("-- body --"))
	fmt.Fprintln(w, draft.BodyText)
	fmt.Fprintln(w)
	fmt.Fprintln(w, output.StyleDim.Render("-- evidence bullets (for web takedown forms) --"))
	for _, b := range draft.EvidenceBullets {
		fmt.Fprintln(w, "- "+b)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, output.StyleDim.Render(
		"WireDepth never sends anything outbound. Operator reviews + sends.",
	))
}

// postJSON does an authenticated POST with body=JSON and returns
// the body bytes. Used by the AI surfaces that don't yet have
// typed Client methods - the public API client adds them on
// next session-pass.
func postJSON(
	urlStr, token string,
	timeout time.Duration,
	body any,
) ([]byte, error) {
	enc, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest("POST", urlStr, bytes.NewReader(enc))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "wd-cli")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer res.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, string(rb))
	}
	return rb, nil
}
