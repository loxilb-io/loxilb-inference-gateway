/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/loxilb-io/loxilb/api/models"
	"github.com/loxilb-io/loxilb/api/restapi/operations"
	tk "github.com/loxilb-io/loxilib"
)

var (
	logFilePath = "/var/log/"
	logFileKey  = "loxilb"
	archivePath = "/var/log/" // Path where rotated logs are stored
	mu          sync.Mutex
)

// LogCursor represents a stateless cursor for log pagination
type LogCursor struct {
	Filename string    `json:"filename"`
	Offset   int64     `json:"offset"`
	ModTime  time.Time `json:"mod_time"`
	FileSize int64     `json:"file_size"`
}

// encodeCursor creates a base64 encoded cursor string
func encodeCursor(cursor LogCursor) string {
	cursorStr := fmt.Sprintf("%s:%d:%d:%d",
		cursor.Filename,
		cursor.Offset,
		cursor.ModTime.Unix(),
		cursor.FileSize)
	return base64.StdEncoding.EncodeToString([]byte(cursorStr))
}

// decodeCursor parses a base64 encoded cursor string
func decodeCursor(cursorStr string) (*LogCursor, error) {
	if cursorStr == "" {
		return nil, nil
	}

	decoded, err := base64.StdEncoding.DecodeString(cursorStr)
	if err != nil {
		return nil, fmt.Errorf("invalid cursor format")
	}

	parts := strings.Split(string(decoded), ":")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid cursor format")
	}

	offset, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid offset in cursor")
	}

	modTime, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp in cursor")
	}

	fileSize, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid file size in cursor")
	}

	return &LogCursor{
		Filename: parts[0],
		Offset:   offset,
		ModTime:  time.Unix(modTime, 0),
		FileSize: fileSize,
	}, nil
}

// validateCursor checks if the cursor is still valid (file hasn't been rotated/modified)
func validateCursor(cursor *LogCursor) bool {
	if cursor == nil {
		return true // No cursor means start from beginning
	}

	filePath := filepath.Join(logFilePath, cursor.Filename)
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return false // File doesn't exist anymore
	}

	// Check if file was modified (rotated) or truncated
	if !fileInfo.ModTime().Equal(cursor.ModTime) || fileInfo.Size() < cursor.FileSize {
		return false
	}

	return true
}

// Reads the next N lines starting from a given cursor position
// If startPos is -1, starts from the end of file (latest logs first)
func readNextLines(file *os.File, startPos int64, numLines int) ([]string, int64) {
	fileInfo, err := file.Stat()
	if err != nil {
		return []string{}, 0
	}
	fileSize := fileInfo.Size()

	// If startPos is -1, we want to start from the end (latest logs first)
	if startPos == -1 {
		return readLastLines(file, fileSize, numLines)
	}

	// Normal forward reading from cursor position
	bufferSize := 4096
	buffer := make([]byte, bufferSize)

	var lines []string
	var line string
	currentPos := startPos

	file.Seek(startPos, os.SEEK_SET) // Start reading from the stored cursor position

	for len(lines) < numLines {
		n, err := file.Read(buffer)
		if err != nil {
			break
		}

		for i := 0; i < n; i++ {
			if buffer[i] == '\n' {
				lines = append(lines, strings.TrimSpace(line))
				line = ""

				if len(lines) >= numLines {
					currentPos += int64(i + 1)
					break
				}
			} else {
				line += string(buffer[i])
			}
		}
		currentPos += int64(n)
	}

	if line != "" && len(lines) < numLines {
		lines = append(lines, strings.TrimSpace(line))
	}

	return lines, currentPos
}

// readLastLines reads the last N lines from the file (newest first)
// Returns lines in reverse chronological order (newest first)
func readLastLines(file *os.File, fileSize int64, numLines int) ([]string, int64) {
	if fileSize == 0 {
		return []string{}, 0
	}

	bufferSize := int64(4096)
	var allContent []byte
	pos := fileSize

	// Read backwards in chunks to build the content
	for pos > 0 {
		chunkSize := bufferSize
		if pos < bufferSize {
			chunkSize = pos
		}

		pos -= chunkSize
		chunk := make([]byte, chunkSize)

		file.Seek(pos, os.SEEK_SET)
		n, err := file.Read(chunk)
		if err != nil {
			break
		}

		// Prepend to content (we're reading backwards)
		allContent = append(chunk[:n], allContent...)

		// Check if we have enough newlines to get numLines
		newlineCount := 0
		for _, b := range allContent {
			if b == '\n' {
				newlineCount++
			}
		}

		// If we have enough lines, we can stop reading
		if newlineCount >= numLines {
			break
		}
	}

	// Split content into lines
	allLines := strings.Split(string(allContent), "\n")

	// Remove empty lines and get the last numLines (excluding the last empty line)
	var validLines []string
	for i := len(allLines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(allLines[i])
		if line != "" {
			validLines = append(validLines, line)
			if len(validLines) >= numLines {
				break
			}
		}
	}

	// Calculate the position where the oldest line in our result starts
	// This will be used as the cursor for the next request
	if len(validLines) > 0 {
		oldestLine := validLines[len(validLines)-1]
		content := string(allContent)
		oldestLineIdx := strings.Index(content, oldestLine)
		if oldestLineIdx >= 0 {
			nextCursor := pos + int64(oldestLineIdx)
			return validLines, nextCursor
		}
	}

	return validLines, pos
}

// Filters logs based on level and keyword
func filterLogs(lines []string, level, keyword string) []string {
	var filtered []string
	for _, line := range lines {
		if (level == "" || strings.Contains(line, level)) &&
			(keyword == "" || strings.Contains(line, keyword)) {
			filtered = append(filtered, line) // No additional quotes
		}
	}
	return filtered
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// getAvailableLogFiles returns a list of available log files with their info
// Prioritizes loxilb{hostname}.log over loxilbdp.log
func getAvailableLogFiles() ([]map[string]interface{}, error) {
	files, err := os.ReadDir(logFilePath)
	if err != nil {
		return nil, err
	}

	var hostnameLogFiles []map[string]interface{}
	var dpLogFiles []map[string]interface{}

	for _, file := range files {
		if strings.HasPrefix(file.Name(), logFileKey) && strings.HasSuffix(file.Name(), ".log") {
			fullPath := filepath.Join(logFilePath, file.Name())
			fileInfo, err := os.Stat(fullPath)
			if err != nil {
				continue
			}

			logFileInfo := map[string]interface{}{
				"filename":     file.Name(),
				"size":         fileInfo.Size(),
				"modified":     fileInfo.ModTime().Unix(),
				"modified_str": fileInfo.ModTime().Format("2006-01-02 15:04:05"),
			}

			// Separate loxilb{hostname}.log from loxilbdp.log
			if file.Name() == "loxilbdp.log" {
				dpLogFiles = append(dpLogFiles, logFileInfo)
			} else {
				hostnameLogFiles = append(hostnameLogFiles, logFileInfo)
			}
		}
	}

	// Sort hostname log files by modification time (newest first)
	for i := 0; i < len(hostnameLogFiles)-1; i++ {
		for j := i + 1; j < len(hostnameLogFiles); j++ {
			if hostnameLogFiles[i]["modified"].(int64) < hostnameLogFiles[j]["modified"].(int64) {
				hostnameLogFiles[i], hostnameLogFiles[j] = hostnameLogFiles[j], hostnameLogFiles[i]
			}
		}
	}

	// Sort dp log files by modification time (newest first)
	for i := 0; i < len(dpLogFiles)-1; i++ {
		for j := i + 1; j < len(dpLogFiles); j++ {
			if dpLogFiles[i]["modified"].(int64) < dpLogFiles[j]["modified"].(int64) {
				dpLogFiles[i], dpLogFiles[j] = dpLogFiles[j], dpLogFiles[i]
			}
		}
	}

	// Return hostname logs first, then dp logs (priority order)
	allLogFiles := append(hostnameLogFiles, dpLogFiles...)
	return allLogFiles, nil
}

// Fetch logs using stateless cursor
func ConfigGetLogs(params operations.GetLogsParams, principal interface{}) middleware.Responder {
	var result models.Logs

	lines := 100 // Default to 100 lines
	if params.Lines != nil {
		lines, _ = strconv.Atoi(*params.Lines)
	}

	// Parse cursor from query parameter - temporary workaround
	var cursor *LogCursor
	cursorParam := params.HTTPRequest.URL.Query().Get("cursor")
	if cursorParam != "" {
		var err error
		cursor, err = decodeCursor(cursorParam)
		if err != nil {
			return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Invalid cursor format"})
		}
	}

	// Check if a specific log file is requested
	requestedFile := params.HTTPRequest.URL.Query().Get("file")

	var logFile string
	var currentLogFilename string

	if requestedFile != "" {
		// Validate and use the requested file
		if !strings.HasPrefix(requestedFile, logFileKey) || !strings.HasSuffix(requestedFile, ".log") {
			return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Invalid log file name"})
		}

		// Security check for path traversal
		if strings.Contains(requestedFile, "..") || strings.Contains(requestedFile, "/") || strings.Contains(requestedFile, "\\") {
			return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Invalid filename"})
		}

		logFile = filepath.Join(logFilePath, requestedFile)
		currentLogFilename = requestedFile

		// Check if file exists
		if _, err := os.Stat(logFile); err != nil {
			return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Requested log file not found"})
		}
	} else {
		// Find the current log file with specific priority:
		// 1st Priority: loxilb{hostname}.log (most recent)
		// 2nd Priority: loxilbdp.log (fallback)
		files, err := os.ReadDir(logFilePath)
		if err != nil {
			return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to read log directory"})
		}

		var latestModTime time.Time
		var fallbackFile string
		var fallbackFilename string
		var fallbackModTime time.Time

		// Find log files with preference: loxilb{hostname}.log > loxilbdp.log
		for _, file := range files {
			if strings.HasPrefix(file.Name(), logFileKey) && strings.HasSuffix(file.Name(), ".log") {
				fullPath := filepath.Join(logFilePath, file.Name())
				fileInfo, err := os.Stat(fullPath)
				if err != nil {
					continue // Skip files we can't stat
				}

				fileName := file.Name()

				// Priority 1: loxilb{hostname}.log (not loxilbdp.log)
				if fileName != "loxilbdp.log" && strings.HasPrefix(fileName, "loxilb") && strings.HasSuffix(fileName, ".log") {
					// This is a loxilb{hostname}.log file - preferred
					if logFile == "" || fileInfo.ModTime().After(latestModTime) {
						logFile = fullPath
						currentLogFilename = fileName
						latestModTime = fileInfo.ModTime()
					}
				} else if fileName == "loxilbdp.log" {
					// Priority 2: loxilbdp.log as fallback
					if fallbackFile == "" || fileInfo.ModTime().After(fallbackModTime) {
						fallbackFile = fullPath
						fallbackFilename = fileName
						fallbackModTime = fileInfo.ModTime()
					}
				}
			}
		}

		// If no loxilb{hostname}.log found, use loxilbdp.log as fallback
		if logFile == "" && fallbackFile != "" {
			logFile = fallbackFile
			currentLogFilename = fallbackFilename
		}
	}

	if logFile == "" {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Log file not found"})
	}

	// If cursor exists but points to different file or is invalid, start fresh
	if cursor != nil && (cursor.Filename != currentLogFilename || !validateCursor(cursor)) {
		cursor = nil // Start from beginning of current file
	}

	file, err := os.Open(logFile)
	if err != nil {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to open log file"})
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to get file info"})
	}

	// Determine starting position
	// For latest-first behavior: start from end if no cursor provided
	startPos := int64(-1) // -1 means start from end
	if cursor != nil {
		startPos = cursor.Offset
	}

	// Read the next batch of lines
	nextLines, nextOffset := readNextLines(file, startPos, lines)

	// Apply filtering if required
	level := derefString(params.Level)
	keyword := derefString(params.Keyword)
	filteredLines := filterLogs(nextLines, level, keyword)

	// Check if there are more logs available
	// For reverse reading: hasMore if nextOffset > 0
	// For forward reading: hasMore if nextOffset < fileSize
	var hasMore bool
	if startPos == -1 {
		// Reading from end - more logs available if cursor > 0
		hasMore = nextOffset > 0
	} else {
		// Reading forward - more logs available if cursor < file size
		hasMore = nextOffset < fileInfo.Size()
	}

	// Create next cursor only if there are more logs
	var nextCursorStr string
	if hasMore {
		nextCursor := LogCursor{
			Filename: currentLogFilename,
			Offset:   nextOffset,
			ModTime:  fileInfo.ModTime(),
			FileSize: fileInfo.Size(),
		}
		nextCursorStr = encodeCursor(nextCursor)
	}

	// Populate the response with logs and metadata
	result.Logs = filteredLines

	// Set pagination metadata directly in response body
	// Note: These fields need to be added to models.Logs struct after API regeneration
	// For now, we'll use reflection or custom response until models are updated

	// Create a custom response structure
	response := map[string]interface{}{
		"logs":       filteredLines,
		"log_file":   currentLogFilename,
		"log_count":  len(filteredLines),
		"total_size": fileInfo.Size(),
		"has_more":   hasMore,
	}

	if hasMore {
		response["next_cursor"] = nextCursorStr
	}

	// Return as custom JSON response
	return middleware.ResponderFunc(func(w http.ResponseWriter, producer runtime.Producer) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Write custom JSON response
		if producer != nil {
			producer.Produce(w, response)
		} else {
			// Fallback JSON encoding
			json.NewEncoder(w).Encode(response)
		}
	})
}

//----------------------------------------------
// Log File Management
//----------------------------------------------

// API to list available active log files (not archives)
func ConfigGetLogFiles(params operations.GetLogArchivesParams, principal interface{}) middleware.Responder {
	logFiles, err := getAvailableLogFiles()
	if err != nil {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to list log files"})
	}

	// Use the same response structure as archives for now
	var result models.LogArchives
	var fileNames []string

	for _, logFile := range logFiles {
		fileNames = append(fileNames, logFile["filename"].(string))
	}

	result.Archives = fileNames
	return operations.NewGetLogArchivesOK().WithPayload(&result)
}

//----------------------------------------------
// Log Archives
//----------------------------------------------

// archiveDirs are scanned for rotated logs: the classic tk.LogIt location
// and the structured-log directory (pkg/loxilog), whose files rotate there.
func archiveDirs() []string {
	return []string{archivePath, filepath.Join(archivePath, "loxilb")}
}

// API to list available log archives
func ConfigGetLogArchives(params operations.GetLogArchivesParams, principal interface{}) middleware.Responder {
	var result models.LogArchives

	seen := map[string]bool{}
	var archives []string
	listed := false
	for _, dir := range archiveDirs() {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		listed = true
		for _, file := range files {
			name := file.Name()
			if file.IsDir() || seen[name] {
				continue
			}
			if strings.HasPrefix(name, "loxilb") && (strings.HasSuffix(name, ".log") || strings.HasSuffix(name, ".log.gz")) {
				seen[name] = true
				archives = append(archives, name)
			}
		}
	}
	if !listed {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to list log archives"})
	}

	result.Archives = archives
	return operations.NewGetLogArchivesOK().WithPayload(&result)
}

// API to download a specific log archive
func ConfigGetLogArchivesFilename(params operations.GetLogArchivesFilenameParams, principal interface{}) middleware.Responder {
	filename := params.Filename

	if filename == "" {
		return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Filename is required"})
	}

	// Security: Prevent path traversal attacks
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") || strings.Contains(filename, "\\") {
		return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Invalid filename"})
	}

	// Validate filename pattern
	if !strings.HasPrefix(filename, "loxilb") || (!strings.HasSuffix(filename, ".log") && !strings.HasSuffix(filename, ".log.gz")) {
		return operations.NewGetLogsBadRequest().WithPayload(&models.Error{Message: "Invalid log file format"})
	}

	// Resolve across the archive directories (filename is already
	// traversal-checked above; Base is belt-and-braces).
	var file *os.File
	var err error
	for _, dir := range archiveDirs() {
		file, err = os.Open(filepath.Join(dir, filepath.Base(filename)))
		if err == nil {
			break
		}
	}
	if err != nil {
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "File not found"})
	}

	// Check if the file is empty
	fileInfo, err := file.Stat()
	if err != nil {
		file.Close()
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "Failed to get file info"})
	}
	if fileInfo.Size() == 0 {
		file.Close()
		return operations.NewGetLogsInternalServerError().WithPayload(&models.Error{Message: "File is empty"})
	}

	// Set headers and send the file
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		defer file.Close()
		w.Header().Set("Content-Disposition", "attachment; filename="+filename)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
		w.WriteHeader(http.StatusOK)
		bytesCopied, err := io.Copy(w, file)
		if err != nil {
			tk.LogIt(tk.LogError, "Failed to copy file content: %s, error: %v\n", file.Name(), err)
		} else {
			tk.LogIt(tk.LogDebug, "Successfully copied %d bytes from file: %s\n", bytesCopied, file.Name())
		}
	})
}
