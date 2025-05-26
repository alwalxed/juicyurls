package processor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"juicyurls/config"
	"juicyurls/internal/checker"
	"juicyurls/internal/types"
	"juicyurls/pkg/writer"
)

func ProcessFile(ctx context.Context, cfg *config.Config) error {
	// 1) Open & stat
	f, err := os.Open(cfg.FilePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if cfg.Verbose {
		fmt.Printf("Streaming %s...\n", cfg.FilePath)
	}

	startTime := time.Now()
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 2) Channels & atomics
	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	urlChan := make(chan string, workers*100)
	resultsChan := make(chan types.Result, workers*10)

	var total, processed, suspicious uint64

	// 3) Reader
	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		scanner := bufio.NewScanner(f)
		buf := make([]byte, config.BufferSize)
		scanner.Buffer(buf, config.BufferSize)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" || line[0] == '#' || line[0] == '/' {
				continue
			}
			atomic.AddUint64(&total, 1)
			select {
			case <-ctx.Done():
				return
			case urlChan <- line:
			}
		}
	}()

	// 4) Close urlChan when reader finishes
	go func() {
		readerWG.Wait()
		close(urlChan)
	}()

	// 5) Workers
	var workerWG sync.WaitGroup
	for i := 0; i < workers; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			uc := cfg.URLChecker
			for {
				select {
				case <-ctx.Done():
					return
				case u, ok := <-urlChan:
					if !ok {
						return
					}
					atomic.AddUint64(&processed, 1)
					if cfg.ValidateURLs && !checker.IsValidURL(u) {
						continue
					}
					if sus, cat, why := uc.IsSuspicious(u); sus {
						atomic.AddUint64(&suspicious, 1)
						select {
						case <-ctx.Done():
							return
						case resultsChan <- types.Result{URL: u, Category: cat, Reason: why}:
						}
					}
				}
			}
		}()
	}

	// 6) Close resultsChan when all workers are done
	go func() {
		workerWG.Wait()
		close(resultsChan)
	}()

	// 7) Writer—and wait until it’s done or context expires
	err = writer.WriteStream(ctx, resultsChan, cfg.OutputPath, cfg.Verbose)
	if err == context.DeadlineExceeded {
		if cfg.Verbose {
			fmt.Println("⏱  Timeout reached, partial results written.")
		}
		return nil
	}

	// 8) Final stats
	if cfg.Verbose {
		elapsed := time.Since(startTime)
		fmt.Printf(
			"Total: %d processed: %d suspicious: %d rate: %.0f URLs/sec\n",
			total, processed, suspicious,
			float64(processed)/elapsed.Seconds(),
		)
	}

	return err
}
