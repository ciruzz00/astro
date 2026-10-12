package detect

import (
	"context"
	"time"

	"github.com/ciruzz00/astro/internal/store"
)

// Analyze runs the rules over the whole timeline of a case, replaces its
// findings and raises the severity of the events they cite. Running it
// again gives the same findings.
func Analyze(ctx context.Context, st *store.Store, caseName string, now time.Time) (Result, error) {
	en := New()
	for off := 0; ; off += store.MaxEventPage {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		page, _, err := st.Events(ctx, caseName, store.EventFilter{Limit: store.MaxEventPage, Offset: off})
		if err != nil {
			return Result{}, err
		}
		for i := range page {
			en.Observe(&page[i])
		}
		if len(page) < store.MaxEventPage {
			break
		}
	}
	res := en.Finish()
	if err := st.ReplaceFindings(ctx, caseName, res.Findings, res.Raise, now); err != nil {
		return Result{}, err
	}
	return res, nil
}
