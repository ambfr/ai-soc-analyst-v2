// internal/analyzer/preview.go
package analyzer

import (
	"io"
	"mime/multipart"
)

type PreviewResult struct {
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"size_bytes"`
	Preview   string `json:"preview"`
}

func PreviewFile(fileHeader *multipart.FileHeader) (PreviewResult, error) {
	file, err := fileHeader.Open()
	if err != nil {
		return PreviewResult{}, err
	}
	defer file.Close()

	buf := make([]byte, 200)
	n, err := io.ReadFull(file, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return PreviewResult{}, err
	}

	return PreviewResult{
		Filename:  fileHeader.Filename,
		SizeBytes: fileHeader.Size,
		Preview:   string(buf[:n]),
	}, nil
}