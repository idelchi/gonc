package encryption

import (
	"golang.org/x/sync/errgroup"
)

// errgroupWrapper is a wrapper around errgroup.Group to set a limit on the number of goroutines.
type errgroupWrapper struct {
	group errgroup.Group
	sem   chan struct{}
}

// SetLimit sets the maximum number of goroutines.
func (g *errgroupWrapper) SetLimit(n int) {
	g.sem = make(chan struct{}, n)
}

// Go starts a new goroutine.
func (g *errgroupWrapper) Go(f func() error) {
	g.group.Go(func() error {
		g.sem <- struct{}{}
		defer func() { <-g.sem }()
		return f()
	})
}

// Wait waits for all goroutines to finish.
func (g *errgroupWrapper) Wait() error {
	return g.group.Wait()
}
