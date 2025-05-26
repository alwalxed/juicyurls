package writer

import (
	"context"
	"fmt"
	"io"
	"os"

	"juicyurls/internal/types" // <--- NEW IMPORT
)

// WriteResults writes results to output file or stdout
func WriteStream(ctx context.Context, in <-chan types.Result,
	outputPath string, verbose bool) error {

	var out io.Writer = os.Stdout
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r, ok := <-in:
			if !ok {
				return nil
			}
			if verbose {
				fmt.Fprintf(out, "%s [%s: %s]\n", r.URL, r.Category, r.Reason)
			} else {
				fmt.Fprintln(out, r.URL)
			}
		}
	}
}
