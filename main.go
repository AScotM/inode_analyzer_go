package main

import (
    "container/heap"
    "crypto/md5"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "os/signal"
    "path/filepath"
    "runtime"
    "sort"
    "strings"
    "sync"
    "sync/atomic"
    "syscall"
    "time"
)

type InodeAnalyzer struct {
    stats           Stats
    threads         int
    followSymlinks  bool
    excludePatterns []string
    totalSize       int64
    processedPaths  map[string]bool
    fileMetadata    sync.Map
    interrupted     bool
    mu              sync.RWMutex
    wg              sync.WaitGroup
    largestHeap     *FileHeap
    oldestHeap      *TimeHeap
    newestHeap      *TimeHeap
    heapMu          sync.Mutex
    progressDone    chan struct{}
}

type Stats struct {
    TotalFiles        int               `json:"total_files"`
    TotalDirs         int               `json:"total_dirs"`
    TotalSymlinks     int               `json:"total_symlinks"`
    TotalSockets      int               `json:"total_sockets"`
    TotalFifos        int               `json:"total_fifos"`
    TotalDevices      int               `json:"total_devices"`
    Extensions        map[string]int    `json:"extensions"`
    LargestFiles      []FileInfo        `json:"largest_files"`
    OldestFiles       []FileInfo        `json:"oldest_files"`
    NewestFiles       []FileInfo        `json:"newest_files"`
    LargestDirs       []DirInfo         `json:"largest_dirs"`
    Permissions       map[string]int    `json:"permissions"`
    Owners            map[string]int    `json:"owners"`
    Groups            map[string]int    `json:"groups"`
    AgeDistribution   map[string]int    `json:"age_distribution"`
    SizeDistribution  map[string]int    `json:"size_distribution"`
    Duplicates        []DuplicateSet    `json:"duplicates"`
    EmptyFiles        int               `json:"empty_files"`
    EmptyDirs         int               `json:"empty_dirs"`
    BrokenSymlinks    int               `json:"broken_symlinks"`
    PermissionDenied  int               `json:"permission_denied"`
    FileTypes         map[string]int    `json:"file_types"`
}

type FileMetadata struct {
    Path        string
    Size        int64
    Modified    time.Time
    Owner       string
    Group       string
    Permissions string
    Extension   string
}

type FileInfo struct {
    Size        int64     `json:"size"`
    Path        string    `json:"path"`
    Modified    time.Time `json:"modified"`
    Owner       string    `json:"owner"`
    Group       string    `json:"group"`
    Permissions string    `json:"permissions"`
}

type DirInfo struct {
    Size        int64  `json:"size"`
    Count       int    `json:"count"`
    Path        string `json:"path"`
    AverageSize int64  `json:"average_size"`
    LargestFile string `json:"largest_file"`
    LargestSize int64  `json:"largest_size"`
}

type DuplicateSet struct {
    Size        int64    `json:"size"`
    Checksum    string   `json:"checksum"`
    Files       []string `json:"files"`
    TotalSize   int64    `json:"total_size"`
    WastedSpace int64    `json:"wasted_space"`
    Count       int      `json:"count"`
}

type FileHeap []FileInfo

func (h FileHeap) Len() int            { return len(h) }
func (h FileHeap) Less(i, j int) bool  { return h[i].Size > h[j].Size }
func (h FileHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *FileHeap) Push(x interface{}) { *h = append(*h, x.(FileInfo)) }
func (h *FileHeap) Pop() interface{} {
    old := *h
    n := len(old)
    x := old[n-1]
    *h = old[0 : n-1]
    return x
}

type TimeHeap []FileInfo

func (h TimeHeap) Len() int            { return len(h) }
func (h TimeHeap) Less(i, j int) bool  { return h[i].Modified.Before(h[j].Modified) }
func (h TimeHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *TimeHeap) Push(x interface{}) { *h = append(*h, x.(FileInfo)) }
func (h *TimeHeap) Pop() interface{} {
    old := *h
    n := len(old)
    x := old[n-1]
    *h = old[0 : n-1]
    return x
}

var sizeCategories = []struct {
    name string
    min  int64
    max  int64
}{
    {"< 1 KB", 0, 1024},
    {"1 KB - 1 MB", 1024, 1024 * 1024},
    {"1 MB - 10 MB", 1024 * 1024, 10 * 1024 * 1024},
    {"10 MB - 100 MB", 10 * 1024 * 1024, 100 * 1024 * 1024},
    {"100 MB - 1 GB", 100 * 1024 * 1024, 1024 * 1024 * 1024},
    {"> 1 GB", 1024 * 1024 * 1024, 1<<63 - 1},
}

var ageCategories = []struct {
    name string
    dur  time.Duration
}{
    {"Today", 24 * time.Hour},
    {"This week", 7 * 24 * time.Hour},
    {"This month", 30 * 24 * time.Hour},
    {"This year", 365 * 24 * time.Hour},
    {"> 1 year", 1<<63 - 1},
}

func NewInodeAnalyzer(threads int, followSymlinks bool, excludePatterns []string) *InodeAnalyzer {
    if threads < 1 {
        threads = runtime.NumCPU()
    }
    
    largestHeap := &FileHeap{}
    oldestHeap := &TimeHeap{}
    newestHeap := &TimeHeap{}
    heap.Init(largestHeap)
    heap.Init(oldestHeap)
    heap.Init(newestHeap)
    
    return &InodeAnalyzer{
        stats: Stats{
            Extensions:      make(map[string]int),
            Permissions:     make(map[string]int),
            Owners:          make(map[string]int),
            Groups:          make(map[string]int),
            AgeDistribution: make(map[string]int),
            SizeDistribution: make(map[string]int),
            FileTypes:       make(map[string]int),
        },
        threads:         threads,
        followSymlinks:  followSymlinks,
        excludePatterns: excludePatterns,
        processedPaths:  make(map[string]bool),
        largestHeap:     largestHeap,
        oldestHeap:      oldestHeap,
        newestHeap:      newestHeap,
        progressDone:    make(chan struct{}),
    }
}

func (ia *InodeAnalyzer) setupSignalHandler() {
    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        fmt.Println("\nInterrupt received, finishing current operations...")
        ia.mu.Lock()
        ia.interrupted = true
        ia.mu.Unlock()
        close(ia.progressDone)
    }()
}

func (ia *InodeAnalyzer) humanReadableSize(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func (ia *InodeAnalyzer) humanReadableNumber(n int) string {
    switch {
    case n >= 1e9:
        return fmt.Sprintf("%.1fB", float64(n)/1e9)
    case n >= 1e6:
        return fmt.Sprintf("%.1fM", float64(n)/1e6)
    case n >= 1e3:
        return fmt.Sprintf("%.1fK", float64(n)/1e3)
    default:
        return fmt.Sprintf("%d", n)
    }
}

func (ia *InodeAnalyzer) shouldExclude(path string) bool {
    base := filepath.Base(path)
    for _, pattern := range ia.excludePatterns {
        if matched, _ := filepath.Match(pattern, path); matched {
            return true
        }
        if matched, _ := filepath.Match(pattern, base); matched {
            return true
        }
    }
    return false
}

func (ia *InodeAnalyzer) categorizeSize(size int64) string {
    for _, cat := range sizeCategories {
        if size >= cat.min && size < cat.max {
            return cat.name
        }
    }
    return sizeCategories[len(sizeCategories)-1].name
}

func (ia *InodeAnalyzer) categorizeAge(modTime time.Time) string {
    age := time.Since(modTime)
    for _, cat := range ageCategories {
        if age < cat.dur {
            return cat.name
        }
    }
    return ageCategories[len(ageCategories)-1].name
}

func (ia *InodeAnalyzer) getOwnerInfo(uid uint32) string {
    return fmt.Sprintf("%d", uid)
}

func (ia *InodeAnalyzer) getGroupInfo(gid uint32) string {
    return fmt.Sprintf("%d", gid)
}

func (ia *InodeAnalyzer) isSocket(mode os.FileMode) bool {
    return mode&os.ModeSocket != 0
}

func (ia *InodeAnalyzer) isFifo(mode os.FileMode) bool {
    return mode&os.ModeNamedPipe != 0
}

func (ia *InodeAnalyzer) isBlockDevice(mode os.FileMode) bool {
    return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
}

func (ia *InodeAnalyzer) isCharDevice(mode os.FileMode) bool {
    return mode&os.ModeCharDevice != 0
}

func (ia *InodeAnalyzer) AnalyzeDirectory(path string, sampleSize int, deepScan, findDuplicates bool, exportJSON, generatePlot string, ageDays *int, saveState, loadState *string, maxDepth *int) {
    ia.setupSignalHandler()
    
    if sampleSize <= 0 {
        sampleSize = 20
    }
    
    if loadState != nil {
        ia.loadCheckpoint(*loadState)
        return
    }

    absPath, err := filepath.Abs(path)
    if err != nil {
        fmt.Printf("Error: Cannot resolve path: %s\n", path)
        return
    }

    info, err := os.Stat(absPath)
    if err != nil || !info.IsDir() {
        fmt.Printf("Error: Path is not a directory: %s\n", path)
        return
    }

    startTime := time.Now()

    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("Inode Analyzer - %s\n", absPath)
    fmt.Println(strings.Repeat("=", 60))
    fmt.Printf("Mode: ")
    if deepScan {
        fmt.Println("Deep")
    } else {
        fmt.Println("Quick")
    }
    if findDuplicates {
        fmt.Println("Duplicate Detection: Enabled")
    }
    if maxDepth != nil {
        fmt.Printf("Max Depth: %d\n", *maxDepth)
    }
    fmt.Println()

    if deepScan {
        ia.deepScanAnalysis(absPath, sampleSize, findDuplicates, ageDays, maxDepth)
    } else {
        ia.quickScanAnalysis(absPath, sampleSize, maxDepth)
    }

    if findDuplicates && !deepScan && !ia.interrupted {
        ia.findDuplicateFiles(absPath)
    }

    if saveState != nil {
        ia.saveCheckpoint(*saveState)
    }

    elapsedTime := time.Since(startTime)
    ia.printReport(elapsedTime)

    if exportJSON != "" {
        ia.exportJSON(exportJSON)
    }

    if generatePlot != "" {
        fmt.Println("\nVisualization generation not implemented")
    }
}

func (ia *InodeAnalyzer) quickScanAnalysis(root string, sampleSize int, maxDepth *int) {
    fmt.Println("Scanning filesystem...")

    baseDepth := 0
    for _, c := range root {
        if c == filepath.Separator {
            baseDepth++
        }
    }

    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        ia.mu.RLock()
        if ia.interrupted {
            ia.mu.RUnlock()
            return filepath.SkipDir
        }
        ia.mu.RUnlock()

        if err != nil {
            ia.mu.Lock()
            ia.stats.PermissionDenied++
            ia.mu.Unlock()
            return nil
        }

        if maxDepth != nil {
            currentDepth := 0
            for _, c := range path[len(root):] {
                if c == filepath.Separator {
                    currentDepth++
                }
            }
            if currentDepth > *maxDepth {
                if info.IsDir() {
                    return filepath.SkipDir
                }
                return nil
            }
        }

        if ia.shouldExclude(path) {
            if info.IsDir() {
                return filepath.SkipDir
            }
            return nil
        }

        mode := info.Mode()

        if info.IsDir() {
            ia.mu.Lock()
            ia.stats.TotalDirs++
            ia.stats.FileTypes["directory"]++
            if ia.isDirEmpty(path) {
                ia.stats.EmptyDirs++
            }
            ia.mu.Unlock()
            return nil
        }

        var stat *syscall.Stat_t
        if sysInfo := info.Sys(); sysInfo != nil {
            stat, _ = sysInfo.(*syscall.Stat_t)
        }

        switch {
        case mode&os.ModeSymlink != 0:
            ia.mu.Lock()
            ia.stats.TotalSymlinks++
            ia.stats.FileTypes["symlink"]++
            if _, err := os.Stat(path); err != nil {
                ia.stats.BrokenSymlinks++
            }
            ia.mu.Unlock()

        case ia.isSocket(mode):
            ia.mu.Lock()
            ia.stats.TotalSockets++
            ia.stats.FileTypes["socket"]++
            ia.mu.Unlock()

        case ia.isFifo(mode):
            ia.mu.Lock()
            ia.stats.TotalFifos++
            ia.stats.FileTypes["fifo"]++
            ia.mu.Unlock()

        case ia.isBlockDevice(mode) || ia.isCharDevice(mode):
            ia.mu.Lock()
            ia.stats.TotalDevices++
            ia.stats.FileTypes["device"]++
            ia.mu.Unlock()

        case mode.IsRegular():
            ia.mu.Lock()
            ia.stats.TotalFiles++
            ia.stats.FileTypes["regular"]++
            ia.mu.Unlock()

            size := info.Size()
            ia.mu.Lock()
            ia.totalSize += size
            ia.mu.Unlock()

            ext := strings.TrimPrefix(filepath.Ext(info.Name()), ".")
            
            owner := "unknown"
            group := "unknown"
            if stat != nil {
                owner = ia.getOwnerInfo(stat.Uid)
                group = ia.getGroupInfo(stat.Gid)
            }
            
            perms := fmt.Sprintf("%04o", mode.Perm())

            ia.mu.Lock()
            if ext != "" {
                ia.stats.Extensions[ext]++
            }
            ia.stats.Permissions[perms]++
            ia.stats.Owners[owner]++
            ia.stats.Groups[group]++

            sizeCat := ia.categorizeSize(size)
            ia.stats.SizeDistribution[sizeCat]++

            if size == 0 {
                ia.stats.EmptyFiles++
            }

            ageCat := ia.categorizeAge(info.ModTime())
            ia.stats.AgeDistribution[ageCat]++

            metadata := FileMetadata{
                Path:        path,
                Size:        size,
                Modified:    info.ModTime(),
                Owner:       owner,
                Group:       group,
                Permissions: perms,
                Extension:   ext,
            }
            ia.fileMetadata.Store(path, metadata)
            ia.mu.Unlock()

            fileInfo := FileInfo{
                Size:        size,
                Path:        path,
                Modified:    info.ModTime(),
                Owner:       owner,
                Group:       group,
                Permissions: perms,
            }

            ia.heapMu.Lock()
            heap.Push(ia.largestHeap, fileInfo)
            if ia.largestHeap.Len() > sampleSize*2 {
                heap.Pop(ia.largestHeap)
            }

            heap.Push(ia.oldestHeap, fileInfo)
            if ia.oldestHeap.Len() > sampleSize*2 {
                heap.Pop(ia.oldestHeap)
            }

            heap.Push(ia.newestHeap, fileInfo)
            if ia.newestHeap.Len() > sampleSize*2 {
                heap.Pop(ia.newestHeap)
            }
            ia.heapMu.Unlock()
        }

        return nil
    })

    if err != nil && !ia.interrupted {
        fmt.Printf("Error walking directory: %v\n", err)
    }

    ia.finalizeStats(sampleSize)
    ia.analyzeLargestDirectories(root, sampleSize)
}

func (ia *InodeAnalyzer) deepScanAnalysis(root string, sampleSize int, findDuplicates bool, ageDays *int, maxDepth *int) {
    fmt.Println("Deep Analysis\n")

    work := make(chan string, ia.threads*2)
    var processed int32
    var totalItems int32

    for i := 0; i < ia.threads; i++ {
        ia.wg.Add(1)
        go ia.deepWorker(work, &processed, &totalItems, ageDays)
    }

    go func() {
        ticker := time.NewTicker(100 * time.Millisecond)
        defer ticker.Stop()
        
        for {
            select {
            case <-ticker.C:
                current := atomic.LoadInt32(&processed)
                total := atomic.LoadInt32(&totalItems)
                
                if total > 0 {
                    pct := float64(current) / float64(total) * 100
                    fmt.Printf("\r  Progress: %.1f%% (%d/%d)", pct, current, total)
                }
                
                if current >= total && total > 0 {
                    return
                }
                
            case <-ia.progressDone:
                return
            }
        }
    }()

    baseDepth := 0
    for _, c := range root {
        if c == filepath.Separator {
            baseDepth++
        }
    }

    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }

        ia.mu.RLock()
        if ia.interrupted {
            ia.mu.RUnlock()
            return filepath.SkipDir
        }
        ia.mu.RUnlock()

        if maxDepth != nil {
            currentDepth := 0
            for _, c := range path[len(root):] {
                if c == filepath.Separator {
                    currentDepth++
                }
            }
            if currentDepth > *maxDepth {
                if info.IsDir() {
                    return filepath.SkipDir
                }
                return nil
            }
        }

        if !ia.shouldExclude(path) {
            atomic.AddInt32(&totalItems, 1)
            select {
            case work <- path:
            case <-ia.progressDone:
                return filepath.SkipDir
            }
        }
        return nil
    })

    close(work)
    ia.wg.Wait()
    close(ia.progressDone)

    if err != nil && !ia.interrupted {
        fmt.Printf("Error walking directory: %v\n", err)
    }

    if !ia.interrupted {
        total := atomic.LoadInt32(&totalItems)
        fmt.Printf("\r  Progress: 100%% (%d/%d)\n", total, total)
    } else {
        fmt.Println("\nScan interrupted - partial results")
    }

    ia.finalizeStats(sampleSize)
    ia.analyzeLargestDirectories(root, sampleSize)

    if findDuplicates && !ia.interrupted {
        ia.findDuplicateFiles(root)
    }
}

func (ia *InodeAnalyzer) deepWorker(work <-chan string, processed, totalItems *int32, ageDays *int) {
    defer ia.wg.Done()
    for path := range work {
        ia.mu.RLock()
        if ia.interrupted {
            ia.mu.RUnlock()
            return
        }
        ia.mu.RUnlock()

        ia.analyzeItemDeep(path, ageDays)
        atomic.AddInt32(processed, 1)
    }
}

func (ia *InodeAnalyzer) analyzeItemDeep(path string, ageDays *int) {
    info, err := os.Lstat(path)
    if err != nil {
        ia.mu.Lock()
        ia.stats.PermissionDenied++
        ia.mu.Unlock()
        return
    }

    var stat *syscall.Stat_t
    if sysInfo := info.Sys(); sysInfo != nil {
        stat, _ = sysInfo.(*syscall.Stat_t)
    }

    mode := info.Mode()

    switch {
    case mode&os.ModeSymlink != 0:
        ia.mu.Lock()
        ia.stats.TotalSymlinks++
        ia.stats.FileTypes["symlink"]++
        if _, err := os.Stat(path); err != nil {
            ia.stats.BrokenSymlinks++
        }
        ia.mu.Unlock()

    case ia.isSocket(mode):
        ia.mu.Lock()
        ia.stats.TotalSockets++
        ia.stats.FileTypes["socket"]++
        ia.mu.Unlock()

    case ia.isFifo(mode):
        ia.mu.Lock()
        ia.stats.TotalFifos++
        ia.stats.FileTypes["fifo"]++
        ia.mu.Unlock()

    case ia.isBlockDevice(mode) || ia.isCharDevice(mode):
        ia.mu.Lock()
        ia.stats.TotalDevices++
        ia.stats.FileTypes["device"]++
        ia.mu.Unlock()

    case info.IsDir():
        ia.mu.Lock()
        ia.stats.TotalDirs++
        ia.stats.FileTypes["directory"]++
        if ia.isDirEmpty(path) {
            ia.stats.EmptyDirs++
        }
        ia.mu.Unlock()

    case mode.IsRegular():
        if ageDays != nil {
            age := time.Since(info.ModTime())
            if age > time.Duration(*ageDays)*24*time.Hour {
                return
            }
        }

        size := info.Size()
        ext := strings.TrimPrefix(filepath.Ext(info.Name()), ".")
        
        owner := "unknown"
        group := "unknown"
        if stat != nil {
            owner = ia.getOwnerInfo(stat.Uid)
            group = ia.getGroupInfo(stat.Gid)
        }
        
        perms := fmt.Sprintf("%04o", mode.Perm())

        ia.mu.Lock()
        ia.stats.TotalFiles++
        ia.stats.FileTypes["regular"]++
        ia.totalSize += size

        if ext != "" {
            ia.stats.Extensions[ext]++
        }
        ia.stats.Permissions[perms]++
        ia.stats.Owners[owner]++
        ia.stats.Groups[group]++

        sizeCat := ia.categorizeSize(size)
        ia.stats.SizeDistribution[sizeCat]++

        if size == 0 {
            ia.stats.EmptyFiles++
        }

        ageCat := ia.categorizeAge(info.ModTime())
        ia.stats.AgeDistribution[ageCat]++

        metadata := FileMetadata{
            Path:        path,
            Size:        size,
            Modified:    info.ModTime(),
            Owner:       owner,
            Group:       group,
            Permissions: perms,
            Extension:   ext,
        }
        ia.fileMetadata.Store(path, metadata)
        ia.mu.Unlock()

        fileInfo := FileInfo{
            Size:        size,
            Path:        path,
            Modified:    info.ModTime(),
            Owner:       owner,
            Group:       group,
            Permissions: perms,
        }

        ia.heapMu.Lock()
        heap.Push(ia.largestHeap, fileInfo)
        if ia.largestHeap.Len() > 1000 {
            heap.Pop(ia.largestHeap)
        }

        heap.Push(ia.oldestHeap, fileInfo)
        if ia.oldestHeap.Len() > 1000 {
            heap.Pop(ia.oldestHeap)
        }

        heap.Push(ia.newestHeap, fileInfo)
        if ia.newestHeap.Len() > 1000 {
            heap.Pop(ia.newestHeap)
        }
        ia.heapMu.Unlock()
    }
}

func (ia *InodeAnalyzer) finalizeStats(sampleSize int) {
    ia.heapMu.Lock()
    defer ia.heapMu.Unlock()

    largest := make([]FileInfo, 0, min(sampleSize, ia.largestHeap.Len()))
    for i := 0; i < min(sampleSize, ia.largestHeap.Len()); i++ {
        largest = append(largest, (*ia.largestHeap)[i])
    }
    ia.stats.LargestFiles = largest

    oldest := make([]FileInfo, 0, min(sampleSize, ia.oldestHeap.Len()))
    for i := 0; i < min(sampleSize, ia.oldestHeap.Len()); i++ {
        oldest = append(oldest, (*ia.oldestHeap)[i])
    }
    ia.stats.OldestFiles = oldest

    newest := make([]FileInfo, 0, min(sampleSize, ia.newestHeap.Len()))
    for i := 0; i < min(sampleSize, ia.newestHeap.Len()); i++ {
        newest = append(newest, (*ia.newestHeap)[i])
    }
    ia.stats.NewestFiles = newest
}

func (ia *InodeAnalyzer) analyzeLargestDirectories(root string, sampleSize int) {
    dirStats := make(map[string]struct {
        size        int64
        count       int
        largest     int64
        largestFile string
    })

    ia.fileMetadata.Range(func(key, value interface{}) bool {
        path := key.(string)
        meta := value.(FileMetadata)
        dir := filepath.Dir(path)
        stats := dirStats[dir]
        stats.size += meta.Size
        stats.count++
        if meta.Size > stats.largest {
            stats.largest = meta.Size
            stats.largestFile = filepath.Base(path)
        }
        dirStats[dir] = stats
        return true
    })

    var dirs []DirInfo
    for path, stats := range dirStats {
        avg := int64(0)
        if stats.count > 0 {
            avg = stats.size / int64(stats.count)
        }
        dirs = append(dirs, DirInfo{
            Size:        stats.size,
            Count:       stats.count,
            Path:        path,
            AverageSize: avg,
            LargestFile: stats.largestFile,
            LargestSize: stats.largest,
        })
    }

    sort.Slice(dirs, func(i, j int) bool {
        return dirs[i].Size > dirs[j].Size
    })

    ia.mu.Lock()
    for i := 0; i < min(sampleSize, len(dirs)); i++ {
        ia.stats.LargestDirs = append(ia.stats.LargestDirs, dirs[i])
    }
    ia.mu.Unlock()
}

func (ia *InodeAnalyzer) findDuplicateFiles(root string) {
    fmt.Println("Duplicate file detection...")

    sizeDict := make(map[int64][]string)
    fileCount := 0

    err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
        ia.mu.RLock()
        if ia.interrupted {
            ia.mu.RUnlock()
            return filepath.SkipDir
        }
        ia.mu.RUnlock()

        if err != nil || info.IsDir() || ia.shouldExclude(path) {
            return nil
        }

        if info.Mode().IsRegular() && info.Size() > 0 {
            sizeDict[info.Size()] = append(sizeDict[info.Size()], path)
            fileCount++
        }
        return nil
    })

    if err != nil || ia.interrupted {
        return
    }

    totalCandidates := 0
    for _, paths := range sizeDict {
        if len(paths) > 1 {
            totalCandidates++
        }
    }

    fmt.Printf("  Files: %s | Candidates: %s\n",
        ia.humanReadableNumber(fileCount),
        ia.humanReadableNumber(totalCandidates))
    fmt.Println("  Computing checksums...")

    processed := 0
    var mu sync.Mutex
    var duplicates []DuplicateSet

    var wg sync.WaitGroup
    work := make(chan []string, len(sizeDict))

    for _, paths := range sizeDict {
        if len(paths) > 1 {
            work <- paths
        }
    }
    close(work)

    for i := 0; i < ia.threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for paths := range work {
                ia.mu.RLock()
                if ia.interrupted {
                    ia.mu.RUnlock()
                    return
                }
                ia.mu.RUnlock()

                checksumDict := make(map[string][]string)
                for _, path := range paths {
                    hash, err := ia.calculateHash(path)
                    if err == nil {
                        checksumDict[hash] = append(checksumDict[hash], path)
                    }
                }

                for hash, dupePaths := range checksumDict {
                    if len(dupePaths) > 1 {
                        info, err := os.Stat(dupePaths[0])
                        if err != nil {
                            continue
                        }
                        size := info.Size()

                        mu.Lock()
                        duplicates = append(duplicates, DuplicateSet{
                            Size:        size,
                            Checksum:    hash,
                            Files:       dupePaths,
                            TotalSize:   size * int64(len(dupePaths)),
                            WastedSpace: size * int64(len(dupePaths)-1),
                            Count:       len(dupePaths),
                        })
                        mu.Unlock()
                    }
                }

                processed++
                if processed%10 == 0 {
                    fmt.Printf("\r      Progress: %d/%d", processed, totalCandidates)
                }
            }
        }()
    }

    wg.Wait()
    fmt.Printf("\r      Progress: %d/%d\n", totalCandidates, totalCandidates)

    sort.Slice(duplicates, func(i, j int) bool {
        return duplicates[i].WastedSpace > duplicates[j].WastedSpace
    })

    ia.mu.Lock()
    ia.stats.Duplicates = duplicates
    ia.mu.Unlock()

    totalWasted := int64(0)
    for _, d := range duplicates {
        totalWasted += d.WastedSpace
    }
    fmt.Printf("  Duplicate sets: %s | Wasted: %s\n",
        ia.humanReadableNumber(len(duplicates)),
        ia.humanReadableSize(totalWasted))
}

func (ia *InodeAnalyzer) calculateHash(path string) (string, error) {
    file, err := os.Open(path)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hash := md5.New()
    if _, err := io.Copy(hash, file); err != nil {
        return "", err
    }

    return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (ia *InodeAnalyzer) isDirEmpty(path string) bool {
    f, err := os.Open(path)
    if err != nil {
        return false
    }
    defer f.Close()

    _, err = f.Readdirnames(1)
    return err == io.EOF
}

func (ia *InodeAnalyzer) printReport(elapsed time.Duration) {
    totalInodes := ia.stats.TotalFiles + ia.stats.TotalDirs + ia.stats.TotalSymlinks +
        ia.stats.TotalSockets + ia.stats.TotalFifos + ia.stats.TotalDevices

    fmt.Println("\n" + strings.Repeat("=", 60))
    fmt.Println("Inode Analysis Report")
    fmt.Println(strings.Repeat("=", 60))

    fmt.Println("\nSummary:")
    fmt.Printf("  Files:               %18s\n", ia.humanReadableNumber(ia.stats.TotalFiles))
    fmt.Printf("  Directories:         %18s\n", ia.humanReadableNumber(ia.stats.TotalDirs))
    fmt.Printf("  Symlinks:            %18s\n", ia.humanReadableNumber(ia.stats.TotalSymlinks))
    fmt.Printf("  Sockets:             %18s\n", ia.humanReadableNumber(ia.stats.TotalSockets))
    fmt.Printf("  FIFOs:               %18s\n", ia.humanReadableNumber(ia.stats.TotalFifos))
    fmt.Printf("  Devices:             %18s\n", ia.humanReadableNumber(ia.stats.TotalDevices))
    fmt.Printf("  %s\n", strings.Repeat("-", 45))
    fmt.Printf("  Total Inodes:        %18s\n", ia.humanReadableNumber(totalInodes))
    fmt.Printf("  Total Size:          %18s\n", ia.humanReadableSize(ia.totalSize))
    fmt.Printf("  Empty Files:         %18s\n", ia.humanReadableNumber(ia.stats.EmptyFiles))
    fmt.Printf("  Empty Directories:   %18s\n", ia.humanReadableNumber(ia.stats.EmptyDirs))
    fmt.Printf("  Broken Symlinks:     %18s\n", ia.humanReadableNumber(ia.stats.BrokenSymlinks))
    fmt.Printf("  Permission Denied:   %18s\n", ia.humanReadableNumber(ia.stats.PermissionDenied))
    fmt.Printf("  Scan Duration:       %18.2fs\n", elapsed.Seconds())

    if len(ia.stats.Duplicates) > 0 {
        totalWasted := int64(0)
        totalDuplicateFiles := 0
        for _, d := range ia.stats.Duplicates {
            totalWasted += d.WastedSpace
            totalDuplicateFiles += d.Count
        }

        fmt.Println("\nDuplicate Files:")
        fmt.Printf("  Duplicate sets:      %18s\n", ia.humanReadableNumber(len(ia.stats.Duplicates)))
        fmt.Printf("  Duplicate files:     %18s\n", ia.humanReadableNumber(totalDuplicateFiles))
        fmt.Printf("  Wasted space:        %18s\n", ia.humanReadableSize(totalWasted))
    }

    if len(ia.stats.Extensions) > 0 {
        fmt.Println("\nExtensions:")
        type extCount struct {
            ext   string
            count int
        }
        var exts []extCount
        for ext, count := range ia.stats.Extensions {
            exts = append(exts, extCount{ext, count})
        }
        sort.Slice(exts, func(i, j int) bool {
            return exts[i].count > exts[j].count
        })
        for _, ec := range exts {
            percentage := float64(ec.count) / float64(max(ia.stats.TotalFiles, 1)) * 100
            fmt.Printf("  .%-20s %12s (%6.1f%%)\n",
                ec.ext,
                ia.humanReadableNumber(ec.count),
                percentage)
        }
    }

    if len(ia.stats.Owners) > 0 {
        fmt.Println("\nOwners:")
        type ownerCount struct {
            owner string
            count int
        }
        var owners []ownerCount
        for owner, count := range ia.stats.Owners {
            owners = append(owners, ownerCount{owner, count})
        }
        sort.Slice(owners, func(i, j int) bool {
            return owners[i].count > owners[j].count
        })
        for _, oc := range owners {
            percentage := float64(oc.count) / float64(max(ia.stats.TotalFiles, 1)) * 100
            name := oc.owner
            if len(name) > 25 {
                name = name[:25]
            }
            fmt.Printf("  %-25s %12s (%6.1f%%)\n",
                name,
                ia.humanReadableNumber(oc.count),
                percentage)
        }
    }

    if len(ia.stats.SizeDistribution) > 0 {
        fmt.Println("\nSize Distribution:")
        cats := make([]string, 0, len(sizeCategories))
        for _, cat := range sizeCategories {
            cats = append(cats, cat.name)
        }
        for _, cat := range cats {
            if count, ok := ia.stats.SizeDistribution[cat]; ok {
                percentage := float64(count) / float64(max(ia.stats.TotalFiles, 1)) * 100
                fmt.Printf("  %-16s %12s (%6.1f%%)\n",
                    cat,
                    ia.humanReadableNumber(count),
                    percentage)
            }
        }
    }

    if len(ia.stats.AgeDistribution) > 0 {
        fmt.Println("\nAge Distribution:")
        cats := []string{"Today", "This week", "This month", "This year", "> 1 year"}
        for _, cat := range cats {
            if count, ok := ia.stats.AgeDistribution[cat]; ok {
                percentage := float64(count) / float64(max(ia.stats.TotalFiles, 1)) * 100
                fmt.Printf("  %-12s %12s (%6.1f%%)\n",
                    cat,
                    ia.humanReadableNumber(count),
                    percentage)
            }
        }
    }

    if ia.interrupted {
        fmt.Println("\n" + strings.Repeat("!", 50))
        fmt.Println("  Scan interrupted - partial results")
        fmt.Println(strings.Repeat("!", 50))
    }
}

func (ia *InodeAnalyzer) exportJSON(outputFile string) {
    totalInodes := ia.stats.TotalFiles + ia.stats.TotalDirs + ia.stats.TotalSymlinks +
        ia.stats.TotalSockets + ia.stats.TotalFifos + ia.stats.TotalDevices

    export := struct {
        Stats
        TotalInodes     int    `json:"total_inodes"`
        TotalSizeHuman  string `json:"total_size_human"`
        TotalSize       int64  `json:"total_size"`
        ScanTime        string `json:"scan_time"`
        Interrupted     bool   `json:"interrupted"`
    }{
        Stats:           ia.stats,
        TotalInodes:     totalInodes,
        TotalSizeHuman:  ia.humanReadableSize(ia.totalSize),
        TotalSize:       ia.totalSize,
        ScanTime:        time.Now().Format("2006-01-02 15:04:05"),
        Interrupted:     ia.interrupted,
    }

    data, err := json.MarshalIndent(export, "", "  ")
    if err != nil {
        fmt.Printf("Error creating JSON: %v\n", err)
        return
    }

    if err := os.WriteFile(outputFile, data, 0644); err != nil {
        fmt.Printf("Error writing JSON: %v\n", err)
        return
    }

    fmt.Printf("\nJSON: %s\n", outputFile)
}

func (ia *InodeAnalyzer) saveCheckpoint(checkpointFile string) {
    checkpoint := struct {
        Stats          Stats
        TotalSize      int64
        ProcessedPaths []string
        Timestamp      string
        Interrupted    bool
    }{
        Stats:          ia.stats,
        TotalSize:      ia.totalSize,
        ProcessedPaths: make([]string, 0, len(ia.processedPaths)),
        Timestamp:      time.Now().Format("2006-01-02 15:04:05"),
        Interrupted:    ia.interrupted,
    }

    for path := range ia.processedPaths {
        if len(checkpoint.ProcessedPaths) < 10000 {
            checkpoint.ProcessedPaths = append(checkpoint.ProcessedPaths, path)
        }
    }

    data, err := json.Marshal(checkpoint)
    if err != nil {
        fmt.Printf("Error creating checkpoint: %v\n", err)
        return
    }

    if err := os.WriteFile(checkpointFile, data, 0644); err != nil {
        fmt.Printf("Error writing checkpoint: %v\n", err)
        return
    }

    fmt.Printf("\nCheckpoint: %s\n", checkpointFile)
}

func (ia *InodeAnalyzer) loadCheckpoint(checkpointFile string) {
    data, err := os.ReadFile(checkpointFile)
    if err != nil {
        fmt.Printf("Failed to read checkpoint: %s\n", checkpointFile)
        return
    }

    var checkpoint struct {
        Stats          Stats
        TotalSize      int64
        ProcessedPaths []string
        Timestamp      string
        Interrupted    bool
    }

    if err := json.Unmarshal(data, &checkpoint); err != nil {
        fmt.Printf("Failed to parse checkpoint: %s\n", checkpointFile)
        return
    }

    ia.stats = checkpoint.Stats
    ia.totalSize = checkpoint.TotalSize
    ia.processedPaths = make(map[string]bool)
    for _, path := range checkpoint.ProcessedPaths {
        ia.processedPaths[path] = true
    }
    ia.interrupted = checkpoint.Interrupted

    fmt.Printf("\nLoaded: %s\n", checkpointFile)
    fmt.Printf("  Date: %s\n", checkpoint.Timestamp)
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

func main() {
    runtime.GOMAXPROCS(runtime.NumCPU())

    analyzer := NewInodeAnalyzer(runtime.NumCPU(), false, nil)

    path := "."
    if len(os.Args) > 1 {
        path = os.Args[1]
    }

    analyzer.AnalyzeDirectory(path, 20, false, false, "", "", nil, nil, nil, nil)
}
