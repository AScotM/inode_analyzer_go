package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode/utf8"
)

type FileInfo struct {
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	Modified    time.Time `json:"modified"`
	Owner       uint32    `json:"uid"`
	Group       uint32    `json:"gid"`
	Permissions string    `json:"permissions"`
	Device      uint64    `json:"device"`
	Inode       uint64    `json:"inode"`
	Links       uint64    `json:"links"`
}

type DirInfo struct {
	Path  string `json:"path"`
	Size  int64  `json:"size"`
	Files int64  `json:"files"`
}

type DuplicateSet struct {
	Size        int64    `json:"size"`
	SHA256      string   `json:"sha256"`
	Files       []string `json:"files"`
	WastedSpace int64    `json:"wasted_space"`
}

type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Path     string `json:"path"`
	Detail   string `json:"detail"`
}

type MountInfo struct {
	MountPoint string `json:"mount_point"`
	FileSystem string `json:"filesystem"`
	Source     string `json:"source"`
	Options    string `json:"options"`
}

type DepthInfo struct {
	Depth       int   `json:"depth"`
	Files       int64 `json:"files"`
	Directories int64 `json:"directories"`
	Bytes       int64 `json:"bytes"`
}

type ExtensionInfo struct {
	Extension string `json:"extension"`
	Files     int64  `json:"files"`
	Bytes     int64  `json:"bytes"`
}

type OwnerInfo struct {
	UID   uint32 `json:"uid"`
	Files int64  `json:"files"`
	Bytes int64  `json:"bytes"`
}

type FileSystemInfo struct {
	BlockSize       uint64 `json:"block_size"`
	Blocks          uint64 `json:"blocks"`
	FreeBlocks      uint64 `json:"free_blocks"`
	AvailableBlocks uint64 `json:"available_blocks"`
	Inodes          uint64 `json:"inodes"`
	FreeInodes      uint64 `json:"free_inodes"`
}

type Stats struct {
	Version                   string           `json:"version"`
	Completed                 time.Time        `json:"completed"`
	Mount                     MountInfo        `json:"mount"`
	FileSystem                FileSystemInfo   `json:"filesystem"`
	Findings                  []Finding        `json:"findings"`
	Depths                    []DepthInfo      `json:"depths"`
	ExtensionsByBytes         []ExtensionInfo  `json:"extensions_by_bytes"`
	OwnersByBytes             []OwnerInfo      `json:"owners_by_bytes"`
	HiddenFiles               int64            `json:"hidden_files"`
	ExecutableFiles           int64            `json:"executable_files"`
	WorldWritable             int64            `json:"world_writable"`
	SetUID                    int64            `json:"setuid"`
	SetGID                    int64            `json:"setgid"`
	StickyFiles               int64            `json:"sticky_files"`
	SparseFiles               int64            `json:"sparse_files"`
	PhysicalBytes             int64            `json:"physical_bytes"`
	LongNames                 int64            `json:"long_names"`
	DeepestPath               int              `json:"deepest_path"`
	SecurityFindingsTruncated bool             `json:"security_findings_truncated"`
	Root                      string           `json:"root"`
	Started                   time.Time        `json:"started"`
	DurationSeconds           float64          `json:"duration_seconds"`
	Interrupted               bool             `json:"interrupted"`
	Files                     int64            `json:"files"`
	Directories               int64            `json:"directories"`
	Symlinks                  int64            `json:"symlinks"`
	BrokenSymlinks            int64            `json:"broken_symlinks"`
	Sockets                   int64            `json:"sockets"`
	FIFOs                     int64            `json:"fifos"`
	Devices                   int64            `json:"devices"`
	Other                     int64            `json:"other"`
	EmptyFiles                int64            `json:"empty_files"`
	EmptyDirectories          int64            `json:"empty_directories"`
	Errors                    int64            `json:"errors"`
	HardlinkAliases           int64            `json:"hardlink_aliases"`
	ScanEntries               int64            `json:"scan_entries"`
	ScanRate                  float64          `json:"scan_rate"`
	LogicalBytes              int64            `json:"logical_bytes"`
	UniqueInodes              int64            `json:"unique_inodes"`
	UniqueLogicalBytes        int64            `json:"unique_logical_bytes"`
	Extensions                map[string]int64 `json:"extensions"`
	Permissions               map[string]int64 `json:"permissions"`
	Owners                    map[string]int64 `json:"owners"`
	Groups                    map[string]int64 `json:"groups"`
	SizeDistribution          map[string]int64 `json:"size_distribution"`
	AgeDistribution           map[string]int64 `json:"age_distribution"`
	LargestFiles              []FileInfo       `json:"largest_files"`
	OldestFiles               []FileInfo       `json:"oldest_files"`
	NewestFiles               []FileInfo       `json:"newest_files"`
	LargestDirs               []DirInfo        `json:"largest_directories"`
	Duplicates                []DuplicateSet   `json:"duplicates"`
}

type Options struct {
	CSV             string
	HTML            string
	XML             string
	Diff            string
	Audit           bool
	AuditLimit      int
	FindName        string
	FindRegex       string
	MinSize         int64
	MaxSize         int64
	ExtensionFilter string
	ShowMount       bool
	Root            string
	Threads         int
	Samples         int
	Deep            bool
	Duplicates      bool
	Follow          bool
	OneFileSystem   bool
	MaxDepth        int
	AgeDays         int
	Excludes        []string
	JSON            string
	SaveState       string
	LoadState       string
	TopLimit        int
	Quiet           bool
	NoProgress      bool
}

type inodeKey struct{ Device, Inode uint64 }

type candidate struct{ FileInfo }

type Analyzer struct {
	options             Options
	stats               Stats
	mu                  sync.Mutex
	dirs                map[string]*DirInfo
	seenFiles           map[inodeKey]struct{}
	duplicateCandidates map[int64][]FileInfo
	seenDirs            map[inodeKey]struct{}
	processed           atomic.Int64
	errorsPrinted       atomic.Int64
	rootDevice          uint64
	uniquePaths         map[inodeKey]string
	depthCounts         map[int]*DepthInfo
	extBytes            map[string]*ExtensionInfo
	ownerBytes          map[uint32]*OwnerInfo
	nameRegex           *regexp.Regexp
}

func newAnalyzer(o Options) *Analyzer {
	return &Analyzer{
		options: o,
		stats:   Stats{Version: "5.0", Root: o.Root, Started: time.Now(), Extensions: map[string]int64{}, Permissions: map[string]int64{}, Owners: map[string]int64{}, Groups: map[string]int64{}, SizeDistribution: map[string]int64{}, AgeDistribution: map[string]int64{}},
		dirs:    make(map[string]*DirInfo), seenFiles: make(map[inodeKey]struct{}), duplicateCandidates: make(map[int64][]FileInfo), seenDirs: make(map[inodeKey]struct{}), uniquePaths: make(map[inodeKey]string), depthCounts: make(map[int]*DepthInfo), extBytes: make(map[string]*ExtensionInfo), ownerBytes: make(map[uint32]*OwnerInfo),
	}
}

func statData(info os.FileInfo) (uint64, uint64, uint64, uint32, uint32) {
	if s, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(s.Dev), s.Ino, uint64(s.Nlink), s.Uid, s.Gid
	}
	return 0, 0, 0, 0, 0
}

func human(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"} {
		f /= 1024
		if f < 1024 {
			return fmt.Sprintf("%.1f %s", f, unit)
		}
	}
	return fmt.Sprintf("%.1f EiB", f)
}

func (a *Analyzer) reportError(path string, err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	a.stats.Errors++
	a.mu.Unlock()
	if !a.options.Quiet && a.errorsPrinted.Add(1) <= 10 {
		fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", path, err)
	}
}

func (a *Analyzer) excluded(path string) bool {
	base := filepath.Base(path)
	for _, p := range a.options.Excludes {
		if ok, _ := filepath.Match(p, base); ok {
			return true
		}
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
	}
	return false
}

func topFile(list []FileInfo, f FileInfo, n int, less func(FileInfo, FileInfo) bool) []FileInfo {
	list = append(list, f)
	sort.Slice(list, func(i, j int) bool { return less(list[i], list[j]) })
	if len(list) > n {
		list = list[:n]
	}
	return list
}

func sizeBucket(n int64) string {
	switch {
	case n < 1024:
		return "< 1 KiB"
	case n < 1024*1024:
		return "1 KiB - 1 MiB"
	case n < 10*1024*1024:
		return "1 MiB - 10 MiB"
	case n < 100*1024*1024:
		return "10 MiB - 100 MiB"
	case n < 1024*1024*1024:
		return "100 MiB - 1 GiB"
	default:
		return ">= 1 GiB"
	}
}

func ageBucket(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < 24*time.Hour:
		return "< 1 day"
	case d < 7*24*time.Hour:
		return "1 - 7 days"
	case d < 30*24*time.Hour:
		return "7 - 30 days"
	case d < 365*24*time.Hour:
		return "30 - 365 days"
	default:
		return ">= 1 year"
	}
}

func (a *Analyzer) addFile(path string, info os.FileInfo) {
	if a.options.MinSize > 0 && info.Size() < a.options.MinSize {
		return
	}
	if a.options.MaxSize > 0 && info.Size() > a.options.MaxSize {
		return
	}
	if a.options.FindName != "" {
		ok, _ := filepath.Match(a.options.FindName, filepath.Base(path))
		if !ok {
			return
		}
	}
	if a.nameRegex != nil && !a.nameRegex.MatchString(path) {
		return
	}
	if a.options.ExtensionFilter != "" && !strings.EqualFold(strings.TrimPrefix(filepath.Ext(path), "."), strings.TrimPrefix(a.options.ExtensionFilter, ".")) {
		return
	}
	if a.options.AgeDays > 0 && time.Since(info.ModTime()) > time.Duration(a.options.AgeDays)*24*time.Hour {
		return
	}
	dev, ino, links, uid, gid := statData(info)
	f := FileInfo{Path: path, Size: info.Size(), Modified: info.ModTime(), Owner: uid, Group: gid, Permissions: fmt.Sprintf("%04o", info.Mode().Perm()), Device: dev, Inode: ino, Links: links}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := &a.stats
	s.Files++
	a.observeFile(path, info, f)
	s.LogicalBytes += f.Size
	if f.Size == 0 {
		s.EmptyFiles++
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext == "" {
		ext = "[none]"
	}
	s.Extensions[ext]++
	s.Permissions[f.Permissions]++
	s.Owners[fmt.Sprint(uid)]++
	s.Groups[fmt.Sprint(gid)]++
	s.SizeDistribution[sizeBucket(f.Size)]++
	s.AgeDistribution[ageBucket(f.Modified)]++
	key := inodeKey{dev, ino}
	if _, exists := a.seenFiles[key]; !exists {
		a.seenFiles[key] = struct{}{}
		s.UniqueInodes++
		s.UniqueLogicalBytes += f.Size
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			s.PhysicalBytes += int64(st.Blocks) * 512
		}
		a.uniquePaths[key] = f.Path
	} else {
		s.HardlinkAliases++
	}
	s.LargestFiles = topFile(s.LargestFiles, f, a.options.Samples, func(x, y FileInfo) bool {
		if x.Size == y.Size {
			return x.Path < y.Path
		}
		return x.Size > y.Size
	})
	s.OldestFiles = topFile(s.OldestFiles, f, a.options.Samples, func(x, y FileInfo) bool {
		if x.Modified.Equal(y.Modified) {
			return x.Path < y.Path
		}
		return x.Modified.Before(y.Modified)
	})
	s.NewestFiles = topFile(s.NewestFiles, f, a.options.Samples, func(x, y FileInfo) bool {
		if x.Modified.Equal(y.Modified) {
			return x.Path < y.Path
		}
		return x.Modified.After(y.Modified)
	})
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if d, ok := a.dirs[dir]; ok {
			d.Size += f.Size
			d.Files++
		}
		if dir == a.options.Root || dir == filepath.Dir(dir) {
			break
		}
	}
	if a.options.Duplicates && f.Size > 0 {
		if a.uniquePaths[key] == f.Path {
			a.duplicateCandidates[f.Size] = append(a.duplicateCandidates[f.Size], f)
		}
	}
}

func (a *Analyzer) addSpecial(info os.FileInfo, path string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch m := info.Mode(); {
	case m&os.ModeSymlink != 0:
		a.stats.Symlinks++
	case m&os.ModeSocket != 0:
		a.stats.Sockets++
	case m&os.ModeNamedPipe != 0:
		a.stats.FIFOs++
	case m&os.ModeDevice != 0:
		a.stats.Devices++
	default:
		a.stats.Other++
	}
}

type dirJob struct {
	path  string
	depth int
}
type fileJob struct {
	path string
	info os.FileInfo
}

func (a *Analyzer) scan(ctx context.Context) {
	rootInfo, err := os.Stat(a.options.Root)
	if err != nil {
		a.reportError(a.options.Root, err)
		return
	}
	if !rootInfo.IsDir() {
		a.reportError(a.options.Root, errors.New("not a directory"))
		return
	}
	a.rootDevice, _, _, _, _ = statData(rootInfo)
	jobs := make(chan fileJob, a.options.Threads*4)
	var wg sync.WaitGroup
	for i := 0; i < a.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				a.addFile(j.path, j.info)
				a.processed.Add(1)
			}
		}()
	}
	stack := []dirJob{{a.options.Root, 0}}
	for len(stack) > 0 && ctx.Err() == nil {
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if a.excluded(d.path) && d.path != a.options.Root {
			continue
		}
		info, err := os.Stat(d.path)
		if err != nil {
			a.reportError(d.path, err)
			continue
		}
		dev, ino, _, _, _ := statData(info)
		if a.options.OneFileSystem && dev != a.rootDevice {
			continue
		}
		key := inodeKey{dev, ino}
		if _, ok := a.seenDirs[key]; ok {
			continue
		}
		a.seenDirs[key] = struct{}{}
		entries, err := os.ReadDir(d.path)
		if err != nil {
			a.reportError(d.path, err)
			continue
		}
		a.mu.Lock()
		a.stats.Directories++
		a.observeDirectory(d.path)
		if len(entries) == 0 {
			a.stats.EmptyDirectories++
		}
		a.dirs[d.path] = &DirInfo{Path: d.path}
		a.mu.Unlock()
		a.processed.Add(1)
		if a.options.MaxDepth > 0 && d.depth >= a.options.MaxDepth {
			continue
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				break
			}
			path := filepath.Join(d.path, entry.Name())
			if a.excluded(path) {
				continue
			}
			fi, err := os.Lstat(path)
			if err != nil {
				a.reportError(path, err)
				continue
			}
			mode := fi.Mode()
			if mode&os.ModeSymlink != 0 {
				a.addSpecial(fi, path)
				a.processed.Add(1)
				target, err := os.Stat(path)
				if err != nil {
					a.mu.Lock()
					a.stats.BrokenSymlinks++
					a.mu.Unlock()
					continue
				}
				if !a.options.Follow {
					continue
				}
				fi = target
				mode = fi.Mode()
			}
			if mode.IsDir() {
				stack = append(stack, dirJob{path, d.depth + 1})
			} else if mode.IsRegular() {
				if a.options.OneFileSystem {
					device, _, _, _, _ := statData(fi)
					if device != a.rootDevice {
						continue
					}
				}
				select {
				case jobs <- fileJob{path, fi}:
				case <-ctx.Done():
				}
			} else if mode&os.ModeSymlink == 0 {
				a.addSpecial(fi, path)
				a.processed.Add(1)
			}
		}
	}
	close(jobs)
	wg.Wait()
	dirs := make([]DirInfo, 0, len(a.dirs))
	for _, d := range a.dirs {
		dirs = append(dirs, *d)
	}
	sort.Slice(dirs, func(i, j int) bool {
		if dirs[i].Size == dirs[j].Size {
			return dirs[i].Path < dirs[j].Path
		}
		return dirs[i].Size > dirs[j].Size
	})
	if len(dirs) > a.options.Samples {
		dirs = dirs[:a.options.Samples]
	}
	a.stats.LargestDirs = dirs
	a.finalizeExtended()
	a.stats.ScanEntries = a.processed.Load()
}

func fileHash(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 128*1024)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (a *Analyzer) detectDuplicates(ctx context.Context) {
	type group struct{ files []FileInfo }
	jobs := make(chan group, a.options.Threads*2)
	results := make(chan DuplicateSet, a.options.Threads*2)
	var wg sync.WaitGroup
	for i := 0; i < a.options.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				byHash := make(map[string][]FileInfo)
				for _, f := range job.files {
					if ctx.Err() != nil {
						return
					}
					before, statErr := os.Stat(f.Path)
					if statErr != nil || !before.Mode().IsRegular() || before.Size() != f.Size || !before.ModTime().Equal(f.Modified) {
						a.reportError(f.Path, fmt.Errorf("file changed before hashing"))
						continue
					}
					hash, err := fileHash(ctx, f.Path)
					after, afterErr := os.Stat(f.Path)
					if err == nil && (afterErr != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime())) {
						err = fmt.Errorf("file changed during hashing")
					}
					if err != nil {
						a.reportError(f.Path, err)
						continue
					}
					byHash[hash] = append(byHash[hash], f)
				}
				for hash, files := range byHash {
					if len(files) < 2 {
						continue
					}
					sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
					unique := make(map[inodeKey]struct{})
					paths := make([]string, 0, len(files))
					for _, f := range files {
						paths = append(paths, f.Path)
						unique[inodeKey{f.Device, f.Inode}] = struct{}{}
					}
					wasted := int64(len(unique)-1) * files[0].Size
					if wasted < 0 {
						wasted = 0
					}
					select {
					case results <- DuplicateSet{Size: files[0].Size, SHA256: hash, Files: paths, WastedSpace: wasted}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, files := range a.duplicateCandidates {
			if len(files) < 2 {
				continue
			}
			select {
			case jobs <- group{files}:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	for result := range results {
		a.stats.Duplicates = append(a.stats.Duplicates, result)
	}
	sort.Slice(a.stats.Duplicates, func(i, j int) bool {
		if a.stats.Duplicates[i].WastedSpace == a.stats.Duplicates[j].WastedSpace {
			return a.stats.Duplicates[i].SHA256 < a.stats.Duplicates[j].SHA256
		}
		return a.stats.Duplicates[i].WastedSpace > a.stats.Duplicates[j].WastedSpace
	})
}

func writeJSON(path string, s Stats) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func readJSON(path string) (Stats, error) {
	var s Stats
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

func printTop(label string, files []FileInfo, limit int) {
	if len(files) == 0 {
		return
	}
	section(label)
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  SIZE\tMODIFIED\tUID:GID\tMODE\tPATH")
	fmt.Fprintln(w, "  ----\t--------\t-------\t----\t----")
	for i, f := range files {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Fprintf(w, "  %s\t%s\t%d:%d\t%s\t%s\n", human(f.Size), f.Modified.Format("2006-01-02"), f.Owner, f.Group, f.Permissions, f.Path)
	}
	w.Flush()
}

func printCounts(label string, m map[string]int64, limit int) {
	if len(m) == 0 {
		return
	}
	type pair struct {
		k string
		v int64
	}
	list := make([]pair, 0, len(m))
	for k, v := range m {
		list = append(list, pair{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v == list[j].v {
			return list[i].k < list[j].k
		}
		return list[i].v > list[j].v
	})
	section(label)
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  CATEGORY\tCOUNT\tSHARE")
	fmt.Fprintln(w, "  --------\t-----\t-----")
	var total int64
	for _, p := range list {
		total += p.v
	}
	for i, p := range list {
		if limit > 0 && i >= limit {
			break
		}
		pct := 0.0
		if total > 0 {
			pct = 100 * float64(p.v) / float64(total)
		}
		fmt.Fprintf(w, "  %s\t%s\t%6.2f%%\n", p.k, number(p.v), pct)
	}
	w.Flush()
	if limit > 0 && len(list) > limit {
		fmt.Printf("  ... %d additional categories omitted\n", len(list)-limit)
	}
}

func number(n int64) string {
	x := fmt.Sprintf("%d", n)
	if len(x) <= 3 {
		return x
	}
	var b strings.Builder
	for i, r := range x {
		if i > 0 && (len(x)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func section(label string) {
	fmt.Printf("\n%s\n%s\n", strings.ToUpper(label), strings.Repeat("-", 92))
}

func metric(w *tabwriter.Writer, label, value, detail string) {
	fmt.Fprintf(w, "  %-24s\t%s\t%s\n", label, value, detail)
}

func report(s Stats, limit int) {
	fmt.Println(strings.Repeat("=", 96))
	fmt.Println("  INODE ANALYZER 5.0   |   LINUX FILESYSTEM FORENSICS")
	fmt.Println(strings.Repeat("=", 96))
	fmt.Printf("  Root:     %s\n", s.Root)
	fmt.Printf("  Started:  %s\n", s.Started.Local().Format("2006-01-02 15:04:05 MST"))
	state := "COMPLETE"
	if s.Interrupted {
		state = "INTERRUPTED / PARTIAL"
	}
	fmt.Printf("  Status:   %s    Duration: %.3fs    Throughput: %.0f entries/s\n", state, s.DurationSeconds, s.ScanRate)
	section("Filesystem summary")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 3, ' ', 0)
	metric(w, "Regular files", number(s.Files), "")
	metric(w, "Directories", number(s.Directories), "")
	metric(w, "Symlinks", number(s.Symlinks), fmt.Sprintf("%s broken", number(s.BrokenSymlinks)))
	metric(w, "Sockets / FIFOs", number(s.Sockets)+" / "+number(s.FIFOs), "")
	metric(w, "Devices / Other", number(s.Devices)+" / "+number(s.Other), "")
	metric(w, "Empty files / directories", number(s.EmptyFiles)+" / "+number(s.EmptyDirectories), "")
	metric(w, "Hard-link aliases", number(s.HardlinkAliases), "additional paths to existing inodes")
	metric(w, "Unique regular inodes", number(s.UniqueInodes), "")
	metric(w, "Logical file bytes", human(s.LogicalBytes), fmt.Sprintf("%s bytes", number(s.LogicalBytes)))
	metric(w, "Unique inode bytes", human(s.UniqueLogicalBytes), "hard-link-adjusted logical size")
	metric(w, "Processed entries", number(s.ScanEntries), "")
	metric(w, "Read/stat errors", number(s.Errors), "")
	w.Flush()
	printExtendedSummary(s, limit)
	printAllExtended(s, limit)
	printCounts("Extensions", s.Extensions, limit)
	printCounts("Permissions", s.Permissions, limit)
	printCounts("Owners (UID)", s.Owners, limit)
	printCounts("Groups (GID)", s.Groups, limit)
	printCounts("Size distribution", s.SizeDistribution, 0)
	printCounts("Age distribution", s.AgeDistribution, 0)
	printTop("Largest files", s.LargestFiles, limit)
	printTop("Oldest files", s.OldestFiles, limit)
	printTop("Newest files", s.NewestFiles, limit)
	if len(s.LargestDirs) > 0 {
		section("Largest directories / recursive logical bytes")
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "  SIZE\tFILES\tPATH")
		fmt.Fprintln(w, "  ----\t-----\t----")
		for i, d := range s.LargestDirs {
			if limit > 0 && i >= limit {
				break
			}
			fmt.Fprintf(w, "  %s\t%s\t%s\n", human(d.Size), number(d.Files), d.Path)
		}
		w.Flush()
	}
	if len(s.Duplicates) > 0 {
		section("Content duplicates / SHA-256")
		var wasted int64
		for _, d := range s.Duplicates {
			wasted += d.WastedSpace
		}
		fmt.Printf("  Sets: %s    Potential logical redundancy: %s\n", number(int64(len(s.Duplicates))), human(wasted))
		for i, d := range s.Duplicates {
			if limit > 0 && i >= limit {
				break
			}
			fmt.Printf("  [%d] %s | %s | %s potential redundancy\n", i+1, human(d.Size), d.SHA256, human(d.WastedSpace))
			for _, p := range d.Files {
				fmt.Printf("       %s\n", p)
			}
		}
	}
	fmt.Println("\n" + strings.Repeat("=", 96))
	fmt.Println("  Read-only analysis. Logical sizes are not physical disk allocation estimates.")
	fmt.Println(strings.Repeat("=", 96))
}

func main() {
	o := Options{}
	flag.StringVar(&o.Root, "path", ".", "Directory to scan")
	flag.IntVar(&o.TopLimit, "top", 20, "Maximum rows per report section (0 means all)")
	flag.BoolVar(&o.Quiet, "quiet", false, "Suppress scan status and warnings")
	flag.BoolVar(&o.NoProgress, "no-progress", false, "Disable periodic progress display")
	flag.IntVar(&o.Threads, "threads", runtime.NumCPU(), "Number of file workers")
	flag.IntVar(&o.Samples, "samples", 20, "Top entries to retain")
	flag.BoolVar(&o.Deep, "deep", false, "Enable detailed scan (retained for compatibility)")
	flag.BoolVar(&o.Duplicates, "duplicates", false, "Detect duplicate file content")
	flag.BoolVar(&o.Follow, "follow", false, "Follow symbolic links, avoiding repeated directory inodes")
	flag.BoolVar(&o.OneFileSystem, "one-file-system", false, "Do not cross filesystem devices")
	flag.IntVar(&o.MaxDepth, "max-depth", 0, "Maximum depth, zero means unlimited")
	flag.IntVar(&o.AgeDays, "age", 0, "Include regular files modified within this many days, zero means all")
	exclude := flag.String("exclude", "", "Comma-separated filepath patterns")
	flag.StringVar(&o.JSON, "json", "", "Write JSON report")
	flag.StringVar(&o.CSV, "csv", "", "Write CSV summary")
	flag.StringVar(&o.HTML, "html", "", "Write standalone HTML report")
	flag.StringVar(&o.XML, "xml", "", "Write XML report")
	flag.StringVar(&o.Diff, "diff", "", "Compare against an earlier JSON snapshot")
	flag.BoolVar(&o.Audit, "audit", false, "Collect permission and filename findings")
	flag.IntVar(&o.AuditLimit, "audit-limit", 1000, "Maximum security findings to retain")
	flag.StringVar(&o.FindName, "name", "", "Include matching filenames (glob)")
	flag.StringVar(&o.FindRegex, "regex", "", "Include paths matching a regular expression")
	flag.Int64Var(&o.MinSize, "min-size", 0, "Minimum regular file size in bytes")
	flag.Int64Var(&o.MaxSize, "max-size", 0, "Maximum regular file size in bytes, zero disables")
	flag.StringVar(&o.ExtensionFilter, "extension", "", "Include only matching file extension")
	flag.BoolVar(&o.ShowMount, "mount", false, "Show filesystem and mount information")
	flag.StringVar(&o.SaveState, "save-state", "", "Save a report snapshot as JSON")
	flag.StringVar(&o.LoadState, "load-state", "", "Load and display a saved report snapshot")
	version := flag.Bool("version", false, "Show version")
	flag.Parse()
	if *version {
		fmt.Printf("Inode Analyzer 5.0 (%s)\n", runtime.Version())
		return
	}
	if o.Threads < 1 || o.Samples < 1 || o.MaxDepth < 0 || o.AgeDays < 0 || o.TopLimit < 0 || o.AuditLimit < 0 || o.MinSize < 0 || o.MaxSize < 0 || (o.MaxSize > 0 && o.MinSize > o.MaxSize) {
		fmt.Fprintln(os.Stderr, "Invalid numeric option")
		os.Exit(2)
	}
	if o.LoadState != "" {
		s, err := readJSON(o.LoadState)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		report(s, o.TopLimit)
		return
	}
	if *exclude != "" {
		for _, p := range strings.Split(*exclude, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				if _, err := filepath.Match(p, ""); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(2)
				}
				o.Excludes = append(o.Excludes, p)
			}
		}
	}
	root, err := filepath.Abs(o.Root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	o.Root = filepath.Clean(root)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	rootInfo, rootErr := os.Stat(o.Root)
	if rootErr != nil || !rootInfo.IsDir() {
		if rootErr == nil {
			rootErr = fmt.Errorf("not a directory")
		}
		fmt.Fprintf(os.Stderr, "Invalid scan root %s: %v\n", o.Root, rootErr)
		os.Exit(1)
	}
	a := newAnalyzer(o)
	if o.FindRegex != "" {
		a.nameRegex, err = regexp.Compile(o.FindRegex)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	a.stats.Mount = lookupMount(o.Root)
	a.stats.FileSystem = filesystemInfo(o.Root)
	if !o.Quiet {
		fmt.Fprintf(os.Stderr, "Scanning %s with %d workers...\n", o.Root, o.Threads)
	}
	done := make(chan struct{})
	if !o.NoProgress && !o.Quiet {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					fmt.Fprintf(os.Stderr, "\rProcessed: %s entries | elapsed: %s", number(a.processed.Load()), time.Since(a.stats.Started).Truncate(time.Second))
				}
			}
		}()
	}
	a.scan(ctx)
	close(done)
	if !o.Quiet && !o.NoProgress {
		fmt.Fprintln(os.Stderr)
	}
	if o.Duplicates && ctx.Err() == nil {
		a.detectDuplicates(ctx)
	}
	a.stats.Interrupted = ctx.Err() != nil
	a.stats.Completed = time.Now()
	a.stats.DurationSeconds = time.Since(a.stats.Started).Seconds()
	if a.stats.DurationSeconds > 0 {
		a.stats.ScanRate = float64(a.stats.ScanEntries) / a.stats.DurationSeconds
	}
	report(a.stats, o.TopLimit)
	if o.JSON != "" {
		if err := writeJSON(o.JSON, a.stats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if o.SaveState != "" {
		if err := writeJSON(o.SaveState, a.stats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if o.CSV != "" {
		if err := writeCSV(o.CSV, a.stats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if o.HTML != "" {
		if err := writeHTML(o.HTML, a.stats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if o.XML != "" {
		if err := writeXML(o.XML, a.stats); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if o.Diff != "" {
		previous, err := readJSON(o.Diff)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		printDiff(previous, a.stats)
	}
	if a.stats.Interrupted {
		os.Exit(130)
	}
	if a.stats.Errors > 0 {
		os.Exit(3)
	}
}

func (a *Analyzer) observeFile(path string, info os.FileInfo, f FileInfo) {
	depth := relativeDepth(a.options.Root, path)
	bucket := a.depthCounts[depth]
	if bucket == nil {
		bucket = &DepthInfo{Depth: depth}
		a.depthCounts[depth] = bucket
	}
	bucket.Files++
	bucket.Bytes += f.Size
	if depth > a.stats.DeepestPath {
		a.stats.DeepestPath = depth
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext == "" {
		ext = "[none]"
	}
	extension := a.extBytes[ext]
	if extension == nil {
		extension = &ExtensionInfo{Extension: ext}
		a.extBytes[ext] = extension
	}
	extension.Files++
	extension.Bytes += f.Size
	owner := a.ownerBytes[f.Owner]
	if owner == nil {
		owner = &OwnerInfo{UID: f.Owner}
		a.ownerBytes[f.Owner] = owner
	}
	owner.Files++
	owner.Bytes += f.Size
	mode := info.Mode()
	if strings.HasPrefix(filepath.Base(path), ".") {
		a.stats.HiddenFiles++
	}
	if mode.Perm()&0111 != 0 {
		a.stats.ExecutableFiles++
	}
	if mode.Perm()&0002 != 0 {
		a.stats.WorldWritable++
	}
	if mode&os.ModeSetuid != 0 {
		a.stats.SetUID++
	}
	if mode&os.ModeSetgid != 0 {
		a.stats.SetGID++
	}
	if mode&os.ModeSticky != 0 {
		a.stats.StickyFiles++
	}
	if utf8.RuneCountInString(filepath.Base(path)) > 200 {
		a.stats.LongNames++
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		allocated := int64(stat.Blocks) * 512
		if f.Size > allocated && f.Size > 4096 {
			a.stats.SparseFiles++
		}
	}
	if a.options.Audit {
		a.auditFile(path, info, f)
	}
}

func (a *Analyzer) observeDirectory(path string) {
	depth := relativeDepth(a.options.Root, path)
	bucket := a.depthCounts[depth]
	if bucket == nil {
		bucket = &DepthInfo{Depth: depth}
		a.depthCounts[depth] = bucket
	}
	bucket.Directories++
	if depth > a.stats.DeepestPath {
		a.stats.DeepestPath = depth
	}
	if !a.options.Audit {
		return
	}
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	mode := info.Mode()
	if mode.Perm()&0002 != 0 && mode&os.ModeSticky == 0 {
		a.addFinding("high", "world-writable-directory", path, "Directory is writable by everyone without sticky bit")
	}
	if mode.Perm()&0020 != 0 && mode.Perm()&0002 != 0 {
		a.addFinding("info", "shared-directory", path, "Directory is writable by group and others")
	}
}

func relativeDepth(root, path string) int {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." {
		return 0
	}
	return strings.Count(relative, string(filepath.Separator)) + 1
}

func (a *Analyzer) addFinding(severity, category, path, detail string) {
	if len(a.stats.Findings) >= a.options.AuditLimit {
		a.stats.SecurityFindingsTruncated = true
		return
	}
	a.stats.Findings = append(a.stats.Findings, Finding{
		Severity: severity,
		Category: category,
		Path:     path,
		Detail:   detail,
	})
}

func (a *Analyzer) auditFile(path string, info os.FileInfo, f FileInfo) {
	mode := info.Mode()
	if mode&os.ModeSetuid != 0 {
		a.addFinding("high", "setuid", path, "Set-user-ID bit is enabled")
	}
	if mode&os.ModeSetgid != 0 {
		a.addFinding("medium", "setgid", path, "Set-group-ID bit is enabled")
	}
	if mode.Perm()&0002 != 0 {
		a.addFinding("medium", "world-writable-file", path, "File is writable by everyone")
	}
	if mode.Perm()&0111 != 0 && mode.Perm()&0002 != 0 {
		a.addFinding("high", "world-writable-executable", path, "Executable file is world-writable")
	}
	if strings.ContainsAny(filepath.Base(path), "\n\r\t") {
		a.addFinding("info", "unusual-filename", path, "Filename contains a control whitespace character")
	}
	if !utf8.ValidString(path) {
		a.addFinding("info", "invalid-utf8", path, "Filename contains invalid UTF-8")
	}
	if len(filepath.Base(path)) > 240 {
		a.addFinding("info", "long-filename", path, "Filename approaches common filesystem component limits")
	}
	if f.Links > 1 {
		a.addFinding("info", "hard-link", path, fmt.Sprintf("Inode has %d hard links", f.Links))
	}
}

func (a *Analyzer) finalizeExtended() {
	a.stats.Depths = make([]DepthInfo, 0, len(a.depthCounts))
	for _, item := range a.depthCounts {
		a.stats.Depths = append(a.stats.Depths, *item)
	}
	sort.Slice(a.stats.Depths, func(i, j int) bool { return a.stats.Depths[i].Depth < a.stats.Depths[j].Depth })
	a.stats.ExtensionsByBytes = make([]ExtensionInfo, 0, len(a.extBytes))
	for _, item := range a.extBytes {
		a.stats.ExtensionsByBytes = append(a.stats.ExtensionsByBytes, *item)
	}
	sort.Slice(a.stats.ExtensionsByBytes, func(i, j int) bool {
		x, y := a.stats.ExtensionsByBytes[i], a.stats.ExtensionsByBytes[j]
		if x.Bytes == y.Bytes {
			return x.Extension < y.Extension
		}
		return x.Bytes > y.Bytes
	})
	a.stats.OwnersByBytes = make([]OwnerInfo, 0, len(a.ownerBytes))
	for _, item := range a.ownerBytes {
		a.stats.OwnersByBytes = append(a.stats.OwnersByBytes, *item)
	}
	sort.Slice(a.stats.OwnersByBytes, func(i, j int) bool {
		x, y := a.stats.OwnersByBytes[i], a.stats.OwnersByBytes[j]
		if x.Bytes == y.Bytes {
			return x.UID < y.UID
		}
		return x.Bytes > y.Bytes
	})
	sort.Slice(a.stats.Findings, func(i, j int) bool {
		x, y := a.stats.Findings[i], a.stats.Findings[j]
		if x.Severity != y.Severity {
			return severityRank(x.Severity) > severityRank(y.Severity)
		}
		if x.Path != y.Path {
			return x.Path < y.Path
		}
		return x.Category < y.Category
	})
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func filesystemInfo(root string) FileSystemInfo {
	var raw syscall.Statfs_t
	if err := syscall.Statfs(root, &raw); err != nil {
		return FileSystemInfo{}
	}
	return FileSystemInfo{
		BlockSize:       uint64(raw.Bsize),
		Blocks:          raw.Blocks,
		FreeBlocks:      raw.Bfree,
		AvailableBlocks: raw.Bavail,
		Inodes:          raw.Files,
		FreeInodes:      raw.Ffree,
	}
}

func unescapeMountField(s string) string {
	replacer := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	return replacer.Replace(s)
}

func lookupMount(root string) MountInfo {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return MountInfo{}
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	best := MountInfo{}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) {
			continue
		}
		mountPoint := unescapeMountField(fields[4])
		if root != mountPoint && !strings.HasPrefix(root, strings.TrimSuffix(mountPoint, "/")+"/") {
			continue
		}
		if len(mountPoint) < len(best.MountPoint) {
			continue
		}
		best = MountInfo{
			MountPoint: mountPoint,
			FileSystem: fields[separator+1],
			Source:     unescapeMountField(fields[separator+2]),
			Options:    fields[5],
		}
	}
	return best
}

func printExtendedSummary(s Stats, limit int) {
	section("Extended inode and allocation metrics")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 3, ' ', 0)
	metric(w, "Physical allocation", human(s.PhysicalBytes), "st_blocks based, includes hard-link aliases")
	metric(w, "Sparse file candidates", number(s.SparseFiles), "logical size exceeds allocated blocks")
	metric(w, "Hidden regular files", number(s.HiddenFiles), "")
	metric(w, "Executable regular files", number(s.ExecutableFiles), "")
	metric(w, "World-writable files", number(s.WorldWritable), "")
	metric(w, "SetUID files", number(s.SetUID), "")
	metric(w, "SetGID files", number(s.SetGID), "")
	metric(w, "Sticky-bit files", number(s.StickyFiles), "")
	metric(w, "Long filenames", number(s.LongNames), "more than 200 Unicode code points")
	metric(w, "Deepest observed path", strconv.Itoa(s.DeepestPath), "relative path components")
	w.Flush()
	if s.Mount.MountPoint != "" {
		printMount(s)
	}
	if len(s.Depths) > 0 {
		printDepths(s.Depths, limit)
	}
	if len(s.ExtensionsByBytes) > 0 {
		printExtensionBytes(s.ExtensionsByBytes, limit)
	}
	if len(s.OwnersByBytes) > 0 {
		printOwnerBytes(s.OwnersByBytes, limit)
	}
	if len(s.Findings) > 0 {
		printFindings(s.Findings, limit)
	}
	if s.SecurityFindingsTruncated {
		fmt.Println("  Audit finding limit reached; results are incomplete")
	}
}

func printMount(s Stats) {
	section("Filesystem and mount")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 3, ' ', 0)
	metric(w, "Mount point", s.Mount.MountPoint, "")
	metric(w, "Filesystem", s.Mount.FileSystem, "")
	metric(w, "Source", s.Mount.Source, "")
	metric(w, "Mount options", s.Mount.Options, "")
	fs := s.FileSystem
	if fs.BlockSize > 0 {
		metric(w, "Block size", number(int64(fs.BlockSize)), "bytes")
		metric(w, "Total blocks", number(int64(fs.Blocks)), "")
		metric(w, "Available blocks", number(int64(fs.AvailableBlocks)), "")
		metric(w, "Total filesystem inodes", number(int64(fs.Inodes)), "")
		metric(w, "Free filesystem inodes", number(int64(fs.FreeInodes)), "")
		if fs.Inodes > 0 {
			metric(w, "Inode utilization", fmt.Sprintf("%.2f%%", 100*float64(fs.Inodes-fs.FreeInodes)/float64(fs.Inodes)), "")
		}
	}
	w.Flush()
}

func printDepths(depths []DepthInfo, limit int) {
	section("Directory depth distribution")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  DEPTH\tFILES\tDIRECTORIES\tLOGICAL BYTES")
	for i, d := range depths {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Fprintf(w, "  %d\t%s\t%s\t%s\n", d.Depth, number(d.Files), number(d.Directories), human(d.Bytes))
	}
	w.Flush()
}

func printExtensionBytes(items []ExtensionInfo, limit int) {
	section("Extensions by logical bytes")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  EXTENSION\tFILES\tLOGICAL BYTES")
	for i, item := range items {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", item.Extension, number(item.Files), human(item.Bytes))
	}
	w.Flush()
}

func printOwnerBytes(items []OwnerInfo, limit int) {
	section("Owners by logical bytes")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  UID\tFILES\tLOGICAL BYTES")
	for i, item := range items {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Fprintf(w, "  %d\t%s\t%s\n", item.UID, number(item.Files), human(item.Bytes))
	}
	w.Flush()
}

func printFindings(items []Finding, limit int) {
	section("Permission and filename audit")
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  SEVERITY\tCATEGORY\tPATH")
	for i, item := range items {
		if limit > 0 && i >= limit {
			break
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", strings.ToUpper(item.Severity), item.Category, item.Path)
	}
	w.Flush()
}

func writeCSV(path string, s Stats) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	records := [][]string{
		{"metric", "value", "detail"},
		{"version", s.Version, ""},
		{"root", s.Root, ""},
		{"started", s.Started.Format(time.RFC3339), ""},
		{"completed", s.Completed.Format(time.RFC3339), ""},
		{"duration_seconds", strconv.FormatFloat(s.DurationSeconds, 'f', 3, 64), ""},
		{"files", strconv.FormatInt(s.Files, 10), ""},
		{"directories", strconv.FormatInt(s.Directories, 10), ""},
		{"symlinks", strconv.FormatInt(s.Symlinks, 10), ""},
		{"broken_symlinks", strconv.FormatInt(s.BrokenSymlinks, 10), ""},
		{"sockets", strconv.FormatInt(s.Sockets, 10), ""},
		{"fifos", strconv.FormatInt(s.FIFOs, 10), ""},
		{"devices", strconv.FormatInt(s.Devices, 10), ""},
		{"errors", strconv.FormatInt(s.Errors, 10), ""},
		{"empty_files", strconv.FormatInt(s.EmptyFiles, 10), ""},
		{"empty_directories", strconv.FormatInt(s.EmptyDirectories, 10), ""},
		{"hardlink_aliases", strconv.FormatInt(s.HardlinkAliases, 10), ""},
		{"unique_inodes", strconv.FormatInt(s.UniqueInodes, 10), ""},
		{"logical_bytes", strconv.FormatInt(s.LogicalBytes, 10), ""},
		{"unique_logical_bytes", strconv.FormatInt(s.UniqueLogicalBytes, 10), ""},
		{"physical_bytes", strconv.FormatInt(s.PhysicalBytes, 10), "may count hardlink aliases"},
		{"sparse_files", strconv.FormatInt(s.SparseFiles, 10), ""},
		{"hidden_files", strconv.FormatInt(s.HiddenFiles, 10), ""},
		{"executable_files", strconv.FormatInt(s.ExecutableFiles, 10), ""},
		{"world_writable", strconv.FormatInt(s.WorldWritable, 10), ""},
		{"setuid", strconv.FormatInt(s.SetUID, 10), ""},
		{"setgid", strconv.FormatInt(s.SetGID, 10), ""},
		{"sticky_files", strconv.FormatInt(s.StickyFiles, 10), ""},
		{"long_names", strconv.FormatInt(s.LongNames, 10), ""},
		{"deepest_path", strconv.Itoa(s.DeepestPath), ""},
		{"mount_point", s.Mount.MountPoint, ""},
		{"filesystem", s.Mount.FileSystem, ""},
		{"mount_source", s.Mount.Source, ""},
	}
	for _, record := range records {
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func htmlEscape(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func htmlRow(label, value string) string {
	return "<tr><th>" + htmlEscape(label) + "</th><td>" + htmlEscape(value) + "</td></tr>\n"
}

func htmlSection(title string) string {
	return "<section><h2>" + htmlEscape(title) + "</h2><table>\n"
}

func htmlEndSection() string { return "</table></section>\n" }

func writeHTML(path string, s Stats) error {
	var b strings.Builder
	b.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	b.WriteString("<title>Inode Analyzer 5.0</title>")
	b.WriteString("<style>:root{color-scheme:dark}body{background:#111827;color:#e5e7eb;font-family:system-ui,sans-serif;max-width:1100px;margin:auto;padding:2rem}h1{letter-spacing:.03em}h2{margin-top:2.5rem;border-bottom:1px solid #374151;padding-bottom:.5rem}p{color:#9ca3af}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #374151;overflow-wrap:anywhere}th{width:35%;color:#93c5fd}tr:hover{background:#1f2937}.tag{border:1px solid #4b5563;border-radius:4px;padding:.25rem .5rem}footer{margin-top:3rem;color:#9ca3af}</style></head><body>")
	b.WriteString("<header><h1>Inode Analyzer 5.0</h1><p>Linux filesystem inventory and diagnostics</p></header>")
	b.WriteString("<p><span class=\"tag\">" + htmlEscape(s.Root) + "</span></p>")
	b.WriteString(htmlSection("Overview"))
	for _, row := range [][2]string{
		{"Version", s.Version},
		{"Started", s.Started.Format(time.RFC3339)},
		{"Completed", s.Completed.Format(time.RFC3339)},
		{"Duration", fmt.Sprintf("%.3f seconds", s.DurationSeconds)},
		{"Regular files", number(s.Files)},
		{"Directories", number(s.Directories)},
		{"Symlinks", number(s.Symlinks)},
		{"Errors", number(s.Errors)},
		{"Logical bytes", human(s.LogicalBytes)},
		{"Unique inode bytes", human(s.UniqueLogicalBytes)},
		{"Physical allocation estimate", human(s.PhysicalBytes)},
		{"Unique inodes", number(s.UniqueInodes)},
		{"Hard-link aliases", number(s.HardlinkAliases)},
		{"Scan entries", number(s.ScanEntries)},
		{"Scan throughput", fmt.Sprintf("%.0f entries/s", s.ScanRate)},
	} {
		b.WriteString(htmlRow(row[0], row[1]))
	}
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Filesystem"))
	b.WriteString(htmlRow("Mount point", s.Mount.MountPoint))
	b.WriteString(htmlRow("Type", s.Mount.FileSystem))
	b.WriteString(htmlRow("Source", s.Mount.Source))
	b.WriteString(htmlRow("Options", s.Mount.Options))
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Permissions and security"))
	for _, row := range [][2]string{
		{"Executable files", number(s.ExecutableFiles)},
		{"World-writable files", number(s.WorldWritable)},
		{"SetUID files", number(s.SetUID)},
		{"SetGID files", number(s.SetGID)},
		{"Sparse candidates", number(s.SparseFiles)},
		{"Hidden files", number(s.HiddenFiles)},
		{"Long filenames", number(s.LongNames)},
		{"Findings retained", number(int64(len(s.Findings)))},
	} {
		b.WriteString(htmlRow(row[0], row[1]))
	}
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Largest files"))
	for _, f := range s.LargestFiles {
		b.WriteString(htmlRow(f.Path, human(f.Size)))
	}
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Largest directories"))
	for _, d := range s.LargestDirs {
		b.WriteString(htmlRow(d.Path, human(d.Size)))
	}
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Extensions by bytes"))
	for _, e := range s.ExtensionsByBytes {
		b.WriteString(htmlRow(e.Extension, fmt.Sprintf("%s across %s files", human(e.Bytes), number(e.Files))))
	}
	b.WriteString(htmlEndSection())
	b.WriteString(htmlSection("Depth distribution"))
	for _, d := range s.Depths {
		b.WriteString(htmlRow(strconv.Itoa(d.Depth), fmt.Sprintf("%s files, %s directories, %s", number(d.Files), number(d.Directories), human(d.Bytes))))
	}
	b.WriteString(htmlEndSection())
	if len(s.Findings) > 0 {
		b.WriteString(htmlSection("Audit findings"))
		for _, f := range s.Findings {
			b.WriteString(htmlRow(f.Severity+" / "+f.Category, f.Path+" — "+f.Detail))
		}
		b.WriteString(htmlEndSection())
	}
	b.WriteString("<footer>Read-only analysis. Sizes may differ from actual recoverable disk space.</footer></body></html>")
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func writeXML(path string, s Stats) error {
	type XMLMetric struct {
		XMLName xml.Name `xml:"metric"`
		Name    string   `xml:"name,attr"`
		Value   string   `xml:",chardata"`
	}
	type XMLReport struct {
		XMLName   xml.Name    `xml:"inode-analyzer"`
		Version   string      `xml:"version,attr"`
		Root      string      `xml:"root"`
		Started   string      `xml:"started"`
		Completed string      `xml:"completed"`
		Metrics   []XMLMetric `xml:"metrics>metric"`
	}
	r := XMLReport{Version: s.Version, Root: s.Root, Started: s.Started.Format(time.RFC3339), Completed: s.Completed.Format(time.RFC3339)}
	for _, entry := range [][2]string{
		{"files", strconv.FormatInt(s.Files, 10)},
		{"directories", strconv.FormatInt(s.Directories, 10)},
		{"symlinks", strconv.FormatInt(s.Symlinks, 10)},
		{"errors", strconv.FormatInt(s.Errors, 10)},
		{"logical_bytes", strconv.FormatInt(s.LogicalBytes, 10)},
		{"physical_bytes", strconv.FormatInt(s.PhysicalBytes, 10)},
		{"unique_inodes", strconv.FormatInt(s.UniqueInodes, 10)},
		{"hardlink_aliases", strconv.FormatInt(s.HardlinkAliases, 10)},
		{"world_writable", strconv.FormatInt(s.WorldWritable, 10)},
		{"setuid", strconv.FormatInt(s.SetUID, 10)},
		{"setgid", strconv.FormatInt(s.SetGID, 10)},
		{"hidden_files", strconv.FormatInt(s.HiddenFiles, 10)},
		{"sparse_files", strconv.FormatInt(s.SparseFiles, 10)},
	} {
		r.Metrics = append(r.Metrics, XMLMetric{Name: entry[0], Value: entry[1]})
	}
	encoded, err := xml.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	data := append([]byte(xml.Header), encoded...)
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func printDiff(old, current Stats) {
	section("Snapshot comparison")
	fmt.Printf("  Previous: %s\n", old.Started.Format(time.RFC3339))
	fmt.Printf("  Current:  %s\n", current.Started.Format(time.RFC3339))
	if old.Root != current.Root {
		fmt.Printf("  WARNING: different scan roots (%s versus %s)\n", old.Root, current.Root)
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  METRIC\tPREVIOUS\tCURRENT\tDELTA")
	for _, entry := range []struct {
		name          string
		before, after int64
	}{
		{"Regular files", old.Files, current.Files},
		{"Directories", old.Directories, current.Directories},
		{"Symlinks", old.Symlinks, current.Symlinks},
		{"Broken symlinks", old.BrokenSymlinks, current.BrokenSymlinks},
		{"Empty files", old.EmptyFiles, current.EmptyFiles},
		{"Empty directories", old.EmptyDirectories, current.EmptyDirectories},
		{"Hard-link aliases", old.HardlinkAliases, current.HardlinkAliases},
		{"Unique inodes", old.UniqueInodes, current.UniqueInodes},
		{"Logical bytes", old.LogicalBytes, current.LogicalBytes},
		{"Unique logical bytes", old.UniqueLogicalBytes, current.UniqueLogicalBytes},
		{"Physical bytes", old.PhysicalBytes, current.PhysicalBytes},
		{"Executable files", old.ExecutableFiles, current.ExecutableFiles},
		{"World-writable", old.WorldWritable, current.WorldWritable},
		{"SetUID files", old.SetUID, current.SetUID},
		{"SetGID files", old.SetGID, current.SetGID},
		{"Sparse candidates", old.SparseFiles, current.SparseFiles},
		{"Hidden files", old.HiddenFiles, current.HiddenFiles},
		{"Errors", old.Errors, current.Errors},
	} {
		delta := entry.after - entry.before
		fmt.Fprintf(w, "  %s\t%s\t%s\t%+d\n", entry.name, number(entry.before), number(entry.after), delta)
	}
	w.Flush()
}

func safeLocalPath(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("empty path")
	}
	return filepath.Abs(raw)
}

func resolveFileURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "" && u.Scheme != "file" {
		return "", errors.New("only local file URLs are supported")
	}
	if u.Scheme == "file" {
		if u.Host != "" && u.Host != "localhost" {
			return "", errors.New("remote file URL not supported")
		}
		return filepath.FromSlash(u.Path), nil
	}
	return safeLocalPath(raw)
}

func serveReport(ctx context.Context, address string, s Stats) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(s)
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	err := server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func countOccurrences(text, needle string) int {
	if needle == "" {
		return 0
	}
	return strings.Count(text, needle)
}

func formatPercentage(part, total int64) string {
	if total <= 0 {
		return "0.00%"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(part)/float64(total))
}

func percentageBar(part, total int64, width int) string {
	if width <= 0 {
		return ""
	}
	if total <= 0 {
		return strings.Repeat(" ", width)
	}
	ratio := float64(part) / float64(total)
	if ratio < 0 {
		ratio = 0
	}
	if ratio > 1 {
		ratio = 1
	}
	filled := int(ratio*float64(width) + 0.5)
	return strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
}

func distributionTotal(distribution map[string]int64) int64 {
	var total int64
	for _, count := range distribution {
		total += count
	}
	return total
}

func topExtensionsByBytes(items []ExtensionInfo, limit int) []ExtensionInfo {
	if limit <= 0 || len(items) <= limit {
		return append([]ExtensionInfo(nil), items...)
	}
	return append([]ExtensionInfo(nil), items[:limit]...)
}

func topOwnersByBytes(items []OwnerInfo, limit int) []OwnerInfo {
	if limit <= 0 || len(items) <= limit {
		return append([]OwnerInfo(nil), items...)
	}
	return append([]OwnerInfo(nil), items[:limit]...)
}

func groupFindingsBySeverity(items []Finding) map[string]int64 {
	counts := make(map[string]int64)
	for _, finding := range items {
		counts[finding.Severity]++
	}
	return counts
}

func groupFindingsByCategory(items []Finding) map[string]int64 {
	counts := make(map[string]int64)
	for _, finding := range items {
		counts[finding.Category]++
	}
	return counts
}

func duplicatePotentialBytes(sets []DuplicateSet) int64 {
	var total int64
	for _, set := range sets {
		total += set.WastedSpace
	}
	return total
}

func duplicateFilesCount(sets []DuplicateSet) int64 {
	var total int64
	for _, set := range sets {
		total += int64(len(set.Files))
	}
	return total
}

func filesystemInodeUsage(fs FileSystemInfo) float64 {
	if fs.Inodes == 0 {
		return 0
	}
	return 100 * float64(fs.Inodes-fs.FreeInodes) / float64(fs.Inodes)
}

func filesystemBlockUsage(fs FileSystemInfo) float64 {
	if fs.Blocks == 0 {
		return 0
	}
	return 100 * float64(fs.Blocks-fs.FreeBlocks) / float64(fs.Blocks)
}

func normalizeExtension(ext string) string {
	ext = strings.ToLower(strings.TrimSpace(ext))
	ext = strings.TrimPrefix(ext, ".")
	if ext == "" {
		return "[none]"
	}
	return ext
}

func normalizedRoot(root string) (string, error) {
	path, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}

func validateGlob(pattern string) error {
	_, err := filepath.Match(pattern, "")
	return err
}

func fileAgeDays(modified, now time.Time) float64 {
	return now.Sub(modified).Hours() / 24
}

func fileSizeRatio(logical, physical int64) float64 {
	if logical <= 0 {
		return 0
	}
	return float64(physical) / float64(logical)
}

func filenameExtension(name string) string {
	return normalizeExtension(filepath.Ext(name))
}

func isHiddenFilename(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".."
}

func hasControlCharacters(name string) bool {
	for _, r := range name {
		if r < 32 || r == 127 {
			return true
		}
	}
	return false
}

func printableFilename(name string) string {
	return strconv.QuoteToASCII(name)
}

func truncatePath(path string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(path)
	if len(runes) <= width {
		return path
	}
	if width <= 3 {
		return string(runes[:width])
	}
	return "..." + string(runes[len(runes)-(width-3):])
}

func longestCommonPrefix(a, b string) string {
	ar, br := []rune(a), []rune(b)
	i := 0
	for i < len(ar) && i < len(br) && ar[i] == br[i] {
		i++
	}
	return string(ar[:i])
}

func countPathComponents(path string) int {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return 0
	}
	return len(strings.Split(strings.Trim(cleaned, string(filepath.Separator)), string(filepath.Separator)))
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func bytesToBlocks(size, blockSize int64) int64 {
	if size <= 0 || blockSize <= 0 {
		return 0
	}
	return (size + blockSize - 1) / blockSize
}

func meanFileSize(totalBytes, totalFiles int64) float64 {
	if totalFiles <= 0 {
		return 0
	}
	return float64(totalBytes) / float64(totalFiles)
}

func medianInt64(sorted []int64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return float64(sorted[n/2])
	}
	return float64(sorted[n/2-1])/2 + float64(sorted[n/2])/2
}

func histogramLabel(size int64) string { return sizeBucket(size) }

func formatElapsed(seconds float64) string {
	if seconds < 0 {
		seconds = 0
	}
	duration := time.Duration(seconds * float64(time.Second))
	return duration.Round(time.Millisecond).String()
}

func safeDelta(before, after int64) int64 {
	if after > 0 && before < 0 && after > int64(^uint64(0)>>1)+before {
		return int64(^uint64(0) >> 1)
	}
	return after - before
}

func isSubpath(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func findMountForPath(mounts []MountInfo, path string) MountInfo {
	best := MountInfo{}
	for _, mount := range mounts {
		if isSubpath(mount.MountPoint, path) && len(mount.MountPoint) > len(best.MountPoint) {
			best = mount
		}
	}
	return best
}

func sortedFindingCategories(items []Finding) []string {
	groups := groupFindingsByCategory(items)
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if groups[keys[i]] == groups[keys[j]] {
			return keys[i] < keys[j]
		}
		return groups[keys[i]] > groups[keys[j]]
	})
	return keys
}

func sortedFindingSeverities(items []Finding) []string {
	groups := groupFindingsBySeverity(items)
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if severityRank(keys[i]) == severityRank(keys[j]) {
			return keys[i] < keys[j]
		}
		return severityRank(keys[i]) > severityRank(keys[j])
	})
	return keys
}

func auditSummary(items []Finding) string {
	counts := groupFindingsBySeverity(items)
	return fmt.Sprintf("high=%d medium=%d low=%d info=%d", counts["high"], counts["medium"], counts["low"], counts["info"])
}

func samplePaths(items []FileInfo, n int) []string {
	if n <= 0 || n > len(items) {
		n = len(items)
	}
	result := make([]string, 0, n)
	for _, item := range items[:n] {
		result = append(result, item.Path)
	}
	return result
}

func relativePaths(root string, paths []string) []string {
	result := make([]string, 0, len(paths))
	for _, path := range paths {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			result = append(result, path)
		} else {
			result = append(result, rel)
		}
	}
	return result
}

func sortFilesBySize(files []FileInfo) []FileInfo {
	result := append([]FileInfo(nil), files...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Size == result[j].Size {
			return result[i].Path < result[j].Path
		}
		return result[i].Size > result[j].Size
	})
	return result
}

func sortFilesByAge(files []FileInfo) []FileInfo {
	result := append([]FileInfo(nil), files...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Modified.Equal(result[j].Modified) {
			return result[i].Path < result[j].Path
		}
		return result[i].Modified.Before(result[j].Modified)
	})
	return result
}

func filterFindings(items []Finding, severity string) []Finding {
	result := make([]Finding, 0)
	for _, item := range items {
		if item.Severity == severity {
			result = append(result, item)
		}
	}
	return result
}

func groupFilesByDevice(files []FileInfo) map[uint64][]FileInfo {
	groups := make(map[uint64][]FileInfo)
	for _, file := range files {
		groups[file.Device] = append(groups[file.Device], file)
	}
	return groups
}

func groupFilesByOwner(files []FileInfo) map[uint32][]FileInfo {
	groups := make(map[uint32][]FileInfo)
	for _, file := range files {
		groups[file.Owner] = append(groups[file.Owner], file)
	}
	return groups
}

func groupFilesByPermission(files []FileInfo) map[string][]FileInfo {
	groups := make(map[string][]FileInfo)
	for _, file := range files {
		groups[file.Permissions] = append(groups[file.Permissions], file)
	}
	return groups
}

func compareFileInfo(a, b FileInfo) int {
	if a.Path < b.Path {
		return -1
	}
	if a.Path > b.Path {
		return 1
	}
	if a.Size < b.Size {
		return -1
	}
	if a.Size > b.Size {
		return 1
	}
	return 0
}

func checksumPrefix(hash string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(hash) {
		return hash
	}
	return hash[:n]
}

func statusString(interrupted bool, errors int64) string {
	if interrupted {
		return "INTERRUPTED"
	}
	if errors > 0 {
		return "COMPLETE WITH ERRORS"
	}
	return "COMPLETE"
}

func normalizeTimestamp(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Local().Format("2006-01-02 15:04:05 MST")
}

func formatFileMode(mode os.FileMode) string {
	return fmt.Sprintf("%04o", mode.Perm())
}

func formatUIDGID(uid, gid uint32) string {
	return fmt.Sprintf("%d:%d", uid, gid)
}

func formatDeviceInode(device, inode uint64) string {
	return fmt.Sprintf("%d:%d", device, inode)
}

func sameInode(a, b FileInfo) bool {
	return a.Device == b.Device && a.Inode == b.Inode
}

func hasDifferentDevice(a, b FileInfo) bool { return a.Device != b.Device }

func sortedMapKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mergeCountMaps(a, b map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(a)+len(b))
	for k, v := range a {
		result[k] += v
	}
	for k, v := range b {
		result[k] += v
	}
	return result
}

func diffCountMaps(before, after map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(before)+len(after))
	for k, v := range after {
		result[k] += v
	}
	for k, v := range before {
		result[k] -= v
	}
	return result
}

func nonzeroCountMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64)
	for k, v := range m {
		if v != 0 {
			result[k] = v
		}
	}
	return result
}

func countByExtension(files []FileInfo) map[string]int64 {
	counts := make(map[string]int64)
	for _, file := range files {
		counts[filenameExtension(file.Path)]++
	}
	return counts
}

func bytesByExtension(files []FileInfo) map[string]int64 {
	counts := make(map[string]int64)
	for _, file := range files {
		counts[filenameExtension(file.Path)] += file.Size
	}
	return counts
}

func countByOwner(files []FileInfo) map[uint32]int64 {
	counts := make(map[uint32]int64)
	for _, file := range files {
		counts[file.Owner]++
	}
	return counts
}

func bytesByOwner(files []FileInfo) map[uint32]int64 {
	counts := make(map[uint32]int64)
	for _, file := range files {
		counts[file.Owner] += file.Size
	}
	return counts
}

func uniqueInodeCount(files []FileInfo) int {
	seen := make(map[inodeKey]struct{})
	for _, file := range files {
		seen[inodeKey{file.Device, file.Inode}] = struct{}{}
	}
	return len(seen)
}

func sumFileSizes(files []FileInfo) int64 {
	var total int64
	for _, file := range files {
		total += file.Size
	}
	return total
}

func sumDirectorySizes(dirs []DirInfo) int64 {
	var total int64
	for _, dir := range dirs {
		total += dir.Size
	}
	return total
}

func sumExtensionBytes(items []ExtensionInfo) int64 {
	var total int64
	for _, item := range items {
		total += item.Bytes
	}
	return total
}

func sumOwnerBytes(items []OwnerInfo) int64 {
	var total int64
	for _, item := range items {
		total += item.Bytes
	}
	return total
}

func sumDepthBytes(items []DepthInfo) int64 {
	var total int64
	for _, item := range items {
		total += item.Bytes
	}
	return total
}

func sumDepthFiles(items []DepthInfo) int64 {
	var total int64
	for _, item := range items {
		total += item.Files
	}
	return total
}

func sumDepthDirectories(items []DepthInfo) int64 {
	var total int64
	for _, item := range items {
		total += item.Directories
	}
	return total
}

func verifySummary(s Stats) []string {
	warnings := make([]string, 0)
	if sumExtensionBytes(s.ExtensionsByBytes) != s.LogicalBytes {
		warnings = append(warnings, "extension byte totals differ from logical byte total")
	}
	if sumOwnerBytes(s.OwnersByBytes) != s.LogicalBytes {
		warnings = append(warnings, "owner byte totals differ from logical byte total")
	}
	if sumDepthFiles(s.Depths) != s.Files {
		warnings = append(warnings, "depth file totals differ from file total")
	}
	if sumDepthDirectories(s.Depths) != s.Directories {
		warnings = append(warnings, "depth directory totals differ from directory total")
	}
	if s.UniqueInodes > s.Files {
		warnings = append(warnings, "unique inode count exceeds regular file count")
	}
	if s.HardlinkAliases+s.UniqueInodes != s.Files {
		warnings = append(warnings, "hard-link and unique inode counts do not reconcile")
	}
	return warnings
}

func printVerification(s Stats) {
	warnings := verifySummary(s)
	section("Internal consistency checks")
	if len(warnings) == 0 {
		fmt.Println("  All summary invariants passed")
		return
	}
	for _, warning := range warnings {
		fmt.Printf("  WARNING: %s\n", warning)
	}
}

func printAuditCategories(items []Finding, limit int) {
	counts := groupFindingsByCategory(items)
	printCounts("Audit categories", counts, limit)
}

func printAuditSeverities(items []Finding) {
	counts := groupFindingsBySeverity(items)
	printCounts("Audit severity distribution", counts, 0)
}

func printDuplicateSummary(sets []DuplicateSet) {
	section("Duplicate storage estimate")
	fmt.Printf("  Duplicate sets: %s\n", number(int64(len(sets))))
	fmt.Printf("  Files in duplicate sets: %s\n", number(duplicateFilesCount(sets)))
	fmt.Printf("  Potential logical redundancy: %s\n", human(duplicatePotentialBytes(sets)))
	fmt.Println("  Actual recoverable bytes depend on hard links, reflinks, compression, and filesystem behavior")
}

func printInodeCapacity(fs FileSystemInfo) {
	if fs.Inodes == 0 {
		return
	}
	section("Filesystem inode capacity")
	fmt.Printf("  Total inodes: %s\n", number(int64(fs.Inodes)))
	fmt.Printf("  Free inodes: %s\n", number(int64(fs.FreeInodes)))
	fmt.Printf("  Used percentage: %.2f%%\n", filesystemInodeUsage(fs))
	fmt.Printf("  Block usage: %.2f%%\n", filesystemBlockUsage(fs))
}

func printScanHealth(s Stats) {
	section("Scan health")
	fmt.Printf("  Status: %s\n", statusString(s.Interrupted, s.Errors))
	fmt.Printf("  Duration: %s\n", formatElapsed(s.DurationSeconds))
	fmt.Printf("  Processed entries: %s\n", number(s.ScanEntries))
	fmt.Printf("  Errors: %s\n", number(s.Errors))
	fmt.Printf("  Throughput: %.0f entries/second\n", s.ScanRate)
}

func printDataQuality(s Stats) {
	section("Data quality notes")
	if s.Interrupted {
		fmt.Println("  Scan was interrupted; all totals may be incomplete")
	}
	if s.Errors > 0 {
		fmt.Println("  Some paths could not be inspected")
	}
	if s.SecurityFindingsTruncated {
		fmt.Println("  Security findings exceeded the configured retention limit")
	}
	if s.HardlinkAliases > 0 {
		fmt.Println("  Logical byte totals include multiple paths pointing to the same inode")
	}
	if len(s.Duplicates) > 0 {
		fmt.Println("  Duplicate estimates are not guaranteed physical savings")
	}
	if s.Files == 0 {
		fmt.Println("  No regular files were counted")
	}
	if !s.Interrupted && s.Errors == 0 {
		fmt.Println("  Traversal completed without reported read/stat errors")
	}
}

func printAllExtended(s Stats, limit int) {
	printScanHealth(s)
	printInodeCapacity(s.FileSystem)
	printVerification(s)
	printAuditSeverities(s.Findings)
	printAuditCategories(s.Findings, limit)
	printDuplicateSummary(s.Duplicates)
	printDataQuality(s)
}
