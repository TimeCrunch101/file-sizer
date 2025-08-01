package main

import (
	"bytes"
	"container/heap"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"
)

// FileEntry holds size and path.
type FileEntry struct {
	Size int64  `json:"size_bytes"`
	Path string `json:"path"`
}

// Result is the scan summary.
type Result struct {
	TotalFiles        int         `json:"total_files"`
	TotalFolders      int         `json:"total_folders"`
	LongestPath       string      `json:"longest_path"`
	LongestPathLength int         `json:"longest_path_length"`
	LargeFiles        []FileEntry `json:"top_largest_files"`
}

type MinHeap []FileEntry

func (h MinHeap) Len() int           { return len(h) }
func (h MinHeap) Less(i, j int) bool { return h[i].Size < h[j].Size }
func (h MinHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *MinHeap) Push(x interface{}) {
	*h = append(*h, x.(FileEntry))
}

func (h *MinHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func humanMB(bytes int64) float64 {
	return float64(bytes) / (1024 * 1024)
}

func scan(root string, followSymlinks bool) (totalFiles, totalDirs int, longestPath string, largest []FileEntry) {
	h := &MinHeap{}
	heap.Init(h)

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: walk error: %v\n", err)
			return nil
		}

		// symlink handling
		if d.Type()&os.ModeSymlink != 0 && !followSymlinks {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		if d.IsDir() {
			if path != root {
				totalDirs++
			}
			return nil
		}

		// file
		totalFiles++

		if len(path) > len(longestPath) {
			longestPath = path
		}

		size := info.Size()
		if h.Len() < 20 {
			heap.Push(h, FileEntry{Size: size, Path: path})
		} else if size > (*h)[0].Size {
			heap.Pop(h)
			heap.Push(h, FileEntry{Size: size, Path: path})
		}
		return nil
	})
	// build largest list
	for h.Len() > 0 {
		e := heap.Pop(h).(FileEntry)
		largest = append(largest, e)
	}
	sort.Slice(largest, func(i, j int) bool { return largest[i].Size > largest[j].Size })
	return
}

func outputHuman(w io.Writer, r Result) {
	fmt.Fprintf(w, "Total file count: %d\n", r.TotalFiles)
	fmt.Fprintf(w, "Total folder count: %d\n", r.TotalFolders)
	fmt.Fprintf(w, "Longest file path (%d chars):\n  %s\n\n", len(r.LongestPath), r.LongestPath)

	fmt.Fprintf(w, "Top %d largest files:\n", len(r.LargeFiles))
	if len(r.LargeFiles) == 0 {
		fmt.Fprintln(w, "  (none found)")
		return
	}
	fmt.Fprintf(w, "%10s  %s\n", "Size (MB)", "Path")
	fmt.Fprintln(w, "--------------------------------------------------------------------------------")
	for _, entry := range r.LargeFiles {
		fmt.Fprintf(w, "%10.3f  %s\n", humanMB(entry.Size), entry.Path)
	}
}

func outputJSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func outputCSV(w io.Writer, r Result) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	if err := cw.Write([]string{"metric", "value"}); err != nil {
		return err
	}
	if err := cw.Write([]string{"total_files", strconv.Itoa(r.TotalFiles)}); err != nil {
		return err
	}
	if err := cw.Write([]string{"total_folders", strconv.Itoa(r.TotalFolders)}); err != nil {
		return err
	}
	if err := cw.Write([]string{"longest_path", r.LongestPath}); err != nil {
		return err
	}
	if err := cw.Write([]string{}); err != nil {
		return err
	}
	if err := cw.Write([]string{"size_mb", "size_bytes", "path"}); err != nil {
		return err
	}
	for _, fe := range r.LargeFiles {
		sizeMB := fmt.Sprintf("%.3f", humanMB(fe.Size))
		if err := cw.Write([]string{sizeMB, strconv.FormatInt(fe.Size, 10), fe.Path}); err != nil {
			return err
		}
	}
	return nil
}

func postJSON(apiURL string, r Result) error {
	data, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("POST", apiURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("api returned %s: %s", resp.Status, string(body))
	}
	// optional: you can log success or ignore
	return nil
}

func main() {
	follow := flag.Bool("follow-symlinks", false, "Follow symbolic links during traversal")
	output := flag.String("output", "human", "Output format: human (default), json, csv")
	outFile := flag.String("out", "", "Write output to this file (default stdout)")
	apiURL := flag.String("api", "", "If provided, POST the JSON result to this API endpoint")

	flag.StringVar(outFile, "o", "", "Write output to this file (shorthand)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--follow-symlinks] [--output=human|json|csv] [--out output_file] <path>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}

	root := flag.Arg(0)
	info, err := os.Stat(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error accessing path %q: %v\n", root, err)
		os.Exit(1)
	}

	var res Result
	if !info.IsDir() {
		res = Result{
			TotalFiles:        1,
			TotalFolders:      0,
			LongestPath:       root,
			LongestPathLength: len(root),
			LargeFiles: []FileEntry{
				{Size: info.Size(), Path: root},
			},
		}

	} else {
		tf, td, lp, largest := scan(root, *follow)
		res = Result{
			TotalFiles:        tf,
			TotalFolders:      td,
			LongestPath:       lp,
			LongestPathLength: len(lp),
			LargeFiles:        largest,
		}

	}

	// determine writer
	var writer io.Writer = os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open output file %q: %v\n", *outFile, err)
			os.Exit(1)
		}
		defer f.Close()
		writer = f
	}

	switch *output {
	case "human":
		outputHuman(writer, res)
	case "json":
		if err := outputJSON(writer, res); err != nil {
			fmt.Fprintf(os.Stderr, "JSON output error: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		if err := outputCSV(writer, res); err != nil {
			fmt.Fprintf(os.Stderr, "CSV output error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown output format %q. Use human, json, or csv.\n", *output)
		os.Exit(1)
	}
	if *apiURL != "" {
		if err := postJSON(*apiURL, res); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to POST to API %q: %v\n", *apiURL, err)
		} else {
			fmt.Fprintf(os.Stderr, "Successfully posted JSON to %s\n", *apiURL)
		}
	}

}
