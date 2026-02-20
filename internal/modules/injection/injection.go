package injection

import (
	"context"
	"regexp"
	"sync"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "injection_shield"

// Pattern represents a compiled detection pattern.
type Pattern struct {
	Name     string
	Category string
	Regex    *regexp.Regexp
	Severity core.Severity
}

// Shield is the Injection Shield module.
type Shield struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	patterns     []Pattern
	mu           sync.RWMutex
	ctx          context.Context
	cancel       context.CancelFunc
	stats        Stats
	fileSentinel *FileSentinel
}

// Stats tracks detection statistics.
type Stats struct {
	mu             sync.Mutex
	TotalScanned   int64
	SQLiDetected   int64
	XSSDetected    int64
	CMDiDetected   int64
	SSRFDetected   int64
	LDAPiDetected  int64
	TemplDetected  int64
	NoSQLDetected  int64
	PathDetected   int64
	UploadDetected int64
	DeserDetected  int64
	CanaryDetected int64
}

func New() *Shield {
	return &Shield{}
}

func (s *Shield) Name() string { return ModuleName }
func (s *Shield) Description() string {
	return "Detects SQL injection, XSS, command injection, SSRF, LDAP injection, template injection, NoSQL injection, and path traversal attacks"
}

func (s *Shield) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()
	s.patterns = compilePatterns()
	s.fileSentinel = &FileSentinel{}
	return nil
}

func (s *Shield) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Shield) HandleEvent(event *core.SecurityEvent) error {
	// Process events that contain request data
	if event.Type == "http_request" || event.Type == "api_request" || event.Type == "query" {
		s.analyzeEvent(event)
	}
	// Process file upload events for binary structure analysis
	if event.Type == "file_upload" {
		s.analyzeFileUpload(event)
	}
	return nil
}
