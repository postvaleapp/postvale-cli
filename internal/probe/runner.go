package probe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// RunnerOptions controls the foreground loop.
type RunnerOptions struct {
	Client       *Client
	Logger       io.Writer
	MinBackoff   time.Duration // shortest sleep after a failure
	MaxBackoff   time.Duration // longest sleep after repeated failures
	CheckRunners map[string]CheckFunc
}

// CheckFunc is the signature each check kind implements. It runs
// one scan against target and returns findings to submit. Caller
// merges per-kind output into one submit request per work item.
type CheckFunc func(ctx context.Context, target string, options map[string]interface{}) ([]Finding, error)

// Run loops poll -> dispatch -> submit. Returns when ctx is canceled
// or an unrecoverable error (auth rejected) surfaces. Transient HTTP
// errors back off exponentially; the server-side rate-limit pool is
// generous enough that 30s+ retries don't lose data.
func Run(ctx context.Context, opts RunnerOptions) error {
	if opts.MinBackoff == 0 {
		opts.MinBackoff = 5 * time.Second
	}
	if opts.MaxBackoff == 0 {
		opts.MaxBackoff = 5 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = io.Discard
	}
	backoff := opts.MinBackoff
	logf := func(format string, a ...interface{}) {
		fmt.Fprintf(opts.Logger, "[wdp] "+format+"\n", a...)
	}

	logf("probe loop starting, api=%s", opts.Client.APIBase)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		resp, err := opts.Client.Poll(ctx)
		if err != nil {
			// 401 / probe-paused are not recoverable in-loop. Bail
			// so the operator can investigate.
			if isAuthError(err) {
				return err
			}
			logf("poll failed: %s (sleeping %s)", err, backoff)
			if !sleep(ctx, backoff) {
				return ctx.Err()
			}
			backoff = nextBackoff(backoff, opts.MaxBackoff)
			continue
		}
		backoff = opts.MinBackoff

		if len(resp.Work) == 0 {
			interval := time.Duration(resp.PollIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 60 * time.Second
			}
			if !sleep(ctx, interval) {
				return ctx.Err()
			}
			continue
		}

		for _, item := range resp.Work {
			runOne(ctx, opts, item, logf)
		}
	}
}

func runOne(ctx context.Context, opts RunnerOptions, item WorkItem, logf func(string, ...interface{})) {
	logf("dispatch id=%s kind=%s target=%s", item.ID, item.Kind, item.Target)
	check, ok := opts.CheckRunners[item.Kind]
	if !ok {
		logf("skip id=%s reason=unknown-kind %q", item.ID, item.Kind)
		return
	}
	findings, err := check(ctx, item.Target, item.Options)
	if err != nil {
		logf("check failed id=%s err=%s", item.ID, err)
		return
	}
	if len(findings) == 0 {
		logf("done id=%s findings=0 (no posture issue)", item.ID)
		return
	}
	resp, err := opts.Client.Submit(ctx, SubmitRequest{
		WorkID:   item.ID,
		Findings: findings,
	})
	if err != nil {
		logf("submit failed id=%s err=%s", item.ID, err)
		return
	}
	logf("done id=%s submitted=%d rejected=%d", item.ID, resp.Accepted, len(resp.Rejections))
}

// PortFromOptions reads an optional "port" int out of the work
// item's options map. Used by TLS / header check kinds.
func PortFromOptions(options map[string]interface{}) int {
	if options == nil {
		return 0
	}
	switch v := options["port"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		return max
	}
	return next
}

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	// statusError prefixes 401 messages with a fixed string; matching
	// on the message keeps us out of a custom error-type rabbit hole.
	s := err.Error()
	return errors.Is(err, ErrNoToken) ||
		// Match the substrings produced by client.statusError() for
		// the unrecoverable status codes.
		(len(s) > 0 && (containsAny(s, []string{"token rejected", "probe paused"})))
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
