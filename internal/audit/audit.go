package audit

import (
	"log"
	"os"
	"time"
)

// AuditLogger handles secure logging of cryptographic operations.
type AuditLogger struct {
	logger *log.Logger
}

// NewAuditLogger initializes a logger for the specified file.
func NewAuditLogger(logFile string) (*AuditLogger, error) {
	file, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &AuditLogger{
		logger: log.New(file, "AUDIT: ", log.Ldate|log.Ltime|log.LUTC),
	}, nil
}

// LogEvent records a security-critical event.
func (a *AuditLogger) LogEvent(event string, details string) {
	a.logger.Printf("[%s] Event: %s | Details: %s", time.Now().UTC().Format(time.RFC3339), event, details)
}
