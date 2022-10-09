package logging

import (
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

type Logger struct {
	zerolog.Logger
}

func New(level string) Logger {
	var l zerolog.Level

	switch strings.ToLower(level) {
	case "error":
		l = zerolog.ErrorLevel
	case "warn":
		l = zerolog.WarnLevel
	case "info":
		l = zerolog.InfoLevel
	case "debug":
		l = zerolog.DebugLevel
	default:
		l = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(l)

	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

	return Logger{
		logger,
	}
}

type Entry struct {
	Service      string        `json:"service"`
	Method       string        `json:"method"`
	Url          string        `json:"url"`
	Query        string        `json:"query"`
	RemoteIP     string        `json:"remote_ip"`
	Status       int           `json:"status"`
	Size         int           `json:"size"`
	ReceivedTime time.Time     `json:"received_time"`
	Duration     time.Duration `json:"duration"`
	UserId       string        `json:"user_id"`
	UserAgent    string        `json:"user_agent"`
	ServerIP     string        `json:"server_ip"`
	RequestId    string        `json:"request_id"`
}
