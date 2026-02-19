package deepfake

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "deepfake_shield"

// Shield is the Deepfake Shield module providing:
// - Heuristic audio analysis (entropy, spectral flatness, silence ratio, bitrate consistency)
// - Heuristic video frame analysis (temporal consistency, metadata anomalies)
// - AI-generated phishing/BEC detection (regex-based email analysis)
// - Domain homoglyph spoofing detection
// - Communication pattern anomaly tracking
type Shield struct {
	logger      zerolog.Logger
	bus         *core.EventBus
	pipeline    *core.AlertPipeline
	cfg         *core.Config
	ctx         context.Context
	cancel      context.CancelFunc
	commTracker *CommunicationTracker
	phishDet    *AIPhishingDetector
	domainCheck *DomainSpoofChecker
	audioAnal   *AudioAnalyzer
	videoAnal   *VideoAnalyzer
}

func New() *Shield { return &Shield{} }

func (s *Shield) Name() string { return ModuleName }
func (s *Shield) Description() string {
	return "Heuristic audio/video deepfake detection, AI-generated phishing detection, domain spoofing, and communication anomaly analysis"
}

func (s *Shield) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.bus = bus
	s.pipeline = pipeline
	s.cfg = cfg
	s.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	s.commTracker = NewCommunicationTracker()
	s.phishDet = NewAIPhishingDetector()
	s.domainCheck = NewDomainSpoofChecker()
	s.audioAnal = NewAudioAnalyzer()
	s.videoAnal = NewVideoAnalyzer()

	go s.commTracker.CleanupLoop(s.ctx)

	s.logger.Info().Msg("deepfake shield started")
	return nil
}

func (s *Shield) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

func (s *Shield) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "voice_call", "audio_message", "audio_upload":
		s.handleAudioEvent(event)
	case "video_call", "video_upload":
		s.handleVideoEvent(event)
	case "email_received", "email_sent", "message_received":
		s.handleCommunicationEvent(event)
	case "executive_request", "wire_transfer_request", "urgent_request":
		s.handleHighValueRequest(event)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Audio Analysis — heuristic deepfake detection on raw bytes (no ML)
// ---------------------------------------------------------------------------

// AudioAnalyzer performs statistical analysis on raw audio data to detect
// synthetic speech. Works on raw PCM bytes or any audio payload.
type AudioAnalyzer struct{}

func NewAudioAnalyzer() *AudioAnalyzer { return &AudioAnalyzer{} }

// AudioResult holds the results of heuristic audio analysis.
type AudioResult struct {
	Score           float64
	Entropy         float64
	SpectralFlat    float64
	SilenceRatio    float64
	ZeroCrossRate   float64
	BitrateStable   bool
	Indicators      []string
}

// Analyze performs heuristic analysis on raw audio bytes.
// It computes byte-level entropy, spectral flatness from PCM samples,
// silence ratio, zero-crossing rate, and bitrate consistency.
func (a *AudioAnalyzer) Analyze(raw []byte) AudioResult {
	result := AudioResult{}
	if len(raw) < 64 {
		return result
	}

	// 1. Byte-level Shannon entropy — synthetic audio tends toward lower entropy
	// (more uniform byte distribution from codec artifacts)
	result.Entropy = byteEntropy(raw)
	// Natural speech typically has entropy 5.5-7.5; synthetic often 4.0-5.5
	if result.Entropy < 5.0 {
		result.Score += 0.25
		result.Indicators = append(result.Indicators, fmt.Sprintf("low byte entropy (%.2f)", result.Entropy))
	} else if result.Entropy < 5.5 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("below-average entropy (%.2f)", result.Entropy))
	}

	// 2. Spectral flatness estimation from PCM-like interpretation of bytes
	// Synthetic audio often has unnaturally flat or peaked spectra
	result.SpectralFlat = estimateSpectralFlatness(raw)
	// Very high flatness (>0.8) suggests white noise or synthesis artifacts
	// Very low flatness (<0.1) suggests pure tones (also synthetic)
	if result.SpectralFlat > 0.85 {
		result.Score += 0.20
		result.Indicators = append(result.Indicators, fmt.Sprintf("high spectral flatness (%.3f)", result.SpectralFlat))
	} else if result.SpectralFlat < 0.05 {
		result.Score += 0.15
		result.Indicators = append(result.Indicators, fmt.Sprintf("very low spectral flatness (%.3f)", result.SpectralFlat))
	}

	// 3. Silence ratio — deepfake audio often has unnatural silence patterns
	result.SilenceRatio = silenceRatio(raw)
	// Natural speech: 30-60% silence. Synthetic: often <15% or >75%
	if result.SilenceRatio < 0.10 {
		result.Score += 0.15
		result.Indicators = append(result.Indicators, fmt.Sprintf("almost no silence (%.1f%%)", result.SilenceRatio*100))
	} else if result.SilenceRatio > 0.80 {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, fmt.Sprintf("excessive silence (%.1f%%)", result.SilenceRatio*100))
	}

	// 4. Zero-crossing rate — synthetic speech often has abnormal ZCR
	result.ZeroCrossRate = zeroCrossingRate(raw)
	// Natural speech ZCR typically 0.02-0.15; synthetic can be outside this
	if result.ZeroCrossRate < 0.005 || result.ZeroCrossRate > 0.30 {
		result.Score += 0.15
		result.Indicators = append(result.Indicators, fmt.Sprintf("abnormal zero-crossing rate (%.4f)", result.ZeroCrossRate))
	}

	// 5. Bitrate consistency — check if byte patterns repeat at suspiciously regular intervals
	result.BitrateStable = checkBitrateConsistency(raw)
	if result.BitrateStable {
		result.Score += 0.10
		result.Indicators = append(result.Indicators, "suspiciously uniform bitrate pattern")
	}

	// Cap at 1.0
	if result.Score > 1.0 {
		result.Score = 1.0
	}

	return result
}

// byteEntropy computes Shannon entropy of a byte stream.
func byteEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]float64
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	entropy := 0.0
	for _, f := range freq {
		if f > 0 {
			p := f / n
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// estimateSpectralFlatness computes a spectral flatness estimate by interpreting
// raw bytes as 16-bit PCM samples and computing the ratio of geometric mean
// to arithmetic mean of the magnitude spectrum (via DFT on small windows).
func estimateSpectralFlatness(data []byte) float64 {
	// Interpret as 16-bit little-endian PCM samples
	numSamples := len(data) / 2
	if numSamples < 256 {
		// Fall back to byte-level analysis for very short data
		return byteSpectralFlatness(data)
	}

	samples := make([]float64, numSamples)
	for i := 0; i < numSamples; i++ {
		samples[i] = float64(int16(binary.LittleEndian.Uint16(data[i*2 : i*2+2])))
	}

	// Compute magnitude spectrum using a simple DFT on a window
	windowSize := 256
	if numSamples < windowSize {
		windowSize = numSamples
	}

	// Average spectral flatness over multiple windows
	numWindows := numSamples / windowSize
	if numWindows == 0 {
		numWindows = 1
	}
	if numWindows > 16 {
		numWindows = 16 // cap to avoid excessive computation
	}

	totalFlatness := 0.0
	for w := 0; w < numWindows; w++ {
		offset := w * windowSize
		if offset+windowSize > numSamples {
			break
		}
		window := samples[offset : offset+windowSize]

		// Compute magnitude spectrum via DFT (only first half — Nyquist)
		halfN := windowSize / 2
		magnitudes := make([]float64, halfN)
		for k := 0; k < halfN; k++ {
			realPart := 0.0
			imagPart := 0.0
			for n := 0; n < windowSize; n++ {
				angle := -2.0 * math.Pi * float64(k) * float64(n) / float64(windowSize)
				realPart += window[n] * math.Cos(angle)
				imagPart += window[n] * math.Sin(angle)
			}
			magnitudes[k] = math.Sqrt(realPart*realPart+imagPart*imagPart) + 1e-10
		}

		// Spectral flatness = geometric mean / arithmetic mean
		logSum := 0.0
		arithSum := 0.0
		for _, m := range magnitudes {
			logSum += math.Log(m)
			arithSum += m
		}
		geoMean := math.Exp(logSum / float64(halfN))
		arithMean := arithSum / float64(halfN)

		if arithMean > 0 {
			totalFlatness += geoMean / arithMean
		}
	}

	return totalFlatness / float64(numWindows)
}

// byteSpectralFlatness is a fallback for very short data — treats bytes as samples.
func byteSpectralFlatness(data []byte) float64 {
	if len(data) < 16 {
		return 0.5
	}
	logSum := 0.0
	arithSum := 0.0
	for _, b := range data {
		v := float64(b) + 1.0
		logSum += math.Log(v)
		arithSum += v
	}
	n := float64(len(data))
	geoMean := math.Exp(logSum / n)
	arithMean := arithSum / n
	if arithMean == 0 {
		return 0
	}
	return geoMean / arithMean
}

// silenceRatio estimates the fraction of the audio that is near-silent.
// Interprets bytes as 16-bit PCM; samples below threshold are "silent".
func silenceRatio(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples == 0 {
		return 0
	}

	silentCount := 0
	threshold := 500.0 // ~1.5% of int16 max — typical silence threshold

	for i := 0; i < numSamples; i++ {
		sample := math.Abs(float64(int16(binary.LittleEndian.Uint16(data[i*2 : i*2+2]))))
		if sample < threshold {
			silentCount++
		}
	}

	return float64(silentCount) / float64(numSamples)
}

// zeroCrossingRate computes how often the signal crosses zero.
func zeroCrossingRate(data []byte) float64 {
	numSamples := len(data) / 2
	if numSamples < 2 {
		return 0
	}

	crossings := 0
	prevSample := int16(binary.LittleEndian.Uint16(data[0:2]))
	for i := 1; i < numSamples; i++ {
		sample := int16(binary.LittleEndian.Uint16(data[i*2 : i*2+2]))
		if (prevSample >= 0 && sample < 0) || (prevSample < 0 && sample >= 0) {
			crossings++
		}
		prevSample = sample
	}

	return float64(crossings) / float64(numSamples-1)
}

// checkBitrateConsistency checks if byte patterns repeat at suspiciously regular intervals,
// which can indicate synthetic audio from a codec with fixed frame sizes.
func checkBitrateConsistency(data []byte) bool {
	if len(data) < 4096 {
		return false
	}

	// Check for repeating patterns at common codec frame sizes
	frameSizes := []int{160, 320, 480, 640, 960, 1024, 2048}
	for _, frameSize := range frameSizes {
		if len(data) < frameSize*4 {
			continue
		}
		// Compare energy across consecutive frames
		numFrames := len(data) / frameSize
		if numFrames > 32 {
			numFrames = 32
		}
		energies := make([]float64, numFrames)
		for f := 0; f < numFrames; f++ {
			offset := f * frameSize
			energy := 0.0
			for i := 0; i < frameSize && offset+i < len(data); i++ {
				energy += float64(data[offset+i]) * float64(data[offset+i])
			}
			energies[f] = energy / float64(frameSize)
		}

		// Check variance of frame energies — suspiciously low variance = synthetic
		mean := 0.0
		for _, e := range energies {
			mean += e
		}
		mean /= float64(len(energies))

		variance := 0.0
		for _, e := range energies {
			diff := e - mean
			variance += diff * diff
		}
		variance /= float64(len(energies))

		// Coefficient of variation
		if mean > 0 {
			cv := math.Sqrt(variance) / mean
			if cv < 0.02 { // extremely uniform — suspicious
				return true
			}
		}
	}

	return false
}

// ---------------------------------------------------------------------------
// Video Analysis — heuristic deepfake detection on raw frame bytes (no ML)
// ---------------------------------------------------------------------------

// VideoAnalyzer performs statistical analysis on video frame data.
type VideoAnalyzer struct{}

func NewVideoAnalyzer() *VideoAnalyzer { return &VideoAnalyzer{} }

// VideoResult holds the results of heuristic video analysis.
type VideoResult struct {
	Score      float64
	Indicators []string
}

// Analyze performs heuristic analysis on raw video frame bytes.
// Checks temporal consistency, frame entropy patterns, and metadata anomalies.
func (v *VideoAnalyzer) Analyze(frames [][]byte, metadata map[string]interface{}) VideoResult {
	result := VideoResult{}

	if len(frames) == 0 {
		return result
	}

	// 1. Frame entropy consistency — deepfake videos often have unnaturally consistent
	// entropy across frames (real video has natural variation from scene changes, motion)
	if len(frames) >= 3 {
		entropies := make([]float64, len(frames))
		for i, frame := range frames {
			entropies[i] = byteEntropy(frame)
		}

		// Compute coefficient of variation of frame entropies
		mean := 0.0
		for _, e := range entropies {
			mean += e
		}
		mean /= float64(len(entropies))

		variance := 0.0
		for _, e := range entropies {
			diff := e - mean
			variance += diff * diff
		}
		variance /= float64(len(entropies))

		if mean > 0 {
			cv := math.Sqrt(variance) / mean
			// Very low variation across frames is suspicious
			if cv < 0.01 {
				result.Score += 0.25
				result.Indicators = append(result.Indicators, fmt.Sprintf("unnaturally consistent frame entropy (CV=%.4f)", cv))
			} else if cv < 0.03 {
				result.Score += 0.10
				result.Indicators = append(result.Indicators, fmt.Sprintf("low frame entropy variation (CV=%.4f)", cv))
			}
		}
	}

	// 2. Inter-frame difference analysis — deepfakes often have smooth, uniform
	// transitions rather than natural motion blur and scene variation
	if len(frames) >= 2 {
		diffs := make([]float64, 0, len(frames)-1)
		for i := 1; i < len(frames); i++ {
			d := frameDifference(frames[i-1], frames[i])
			diffs = append(diffs, d)
		}

		// Check if inter-frame differences are suspiciously uniform
		if len(diffs) >= 2 {
			mean := 0.0
			for _, d := range diffs {
				mean += d
			}
			mean /= float64(len(diffs))

			variance := 0.0
			for _, d := range diffs {
				diff := d - mean
				variance += diff * diff
			}
			variance /= float64(len(diffs))

			if mean > 0 {
				cv := math.Sqrt(variance) / mean
				if cv < 0.05 {
					result.Score += 0.20
					result.Indicators = append(result.Indicators, "unnaturally uniform frame transitions")
				}
			}

			// Very low inter-frame difference can indicate static/looped content
			if mean < 0.5 {
				result.Score += 0.15
				result.Indicators = append(result.Indicators, "suspiciously low inter-frame variation")
			}
		}
	}

	// 3. Metadata anomaly checks
	if metadata != nil {
		// Check for missing or suspicious codec info
		if codec, ok := metadata["codec"].(string); ok {
			codec = strings.ToLower(codec)
			// Some deepfake tools leave specific codec signatures
			suspiciousCodecs := []string{"rawvideo", "ffv1", "lagarith"}
			for _, sc := range suspiciousCodecs {
				if strings.Contains(codec, sc) {
					result.Score += 0.10
					result.Indicators = append(result.Indicators, fmt.Sprintf("unusual codec: %s", codec))
					break
				}
			}
		}

		// Check for resolution mismatches (e.g., face region at different resolution)
		if faceRes, ok := metadata["face_resolution"].(float64); ok {
			if frameRes, ok := metadata["frame_resolution"].(float64); ok {
				if faceRes > 0 && frameRes > 0 {
					ratio := faceRes / frameRes
					if ratio < 0.3 || ratio > 3.0 {
						result.Score += 0.15
						result.Indicators = append(result.Indicators, "face/frame resolution mismatch")
					}
				}
			}
		}

		// Check for temporal metadata inconsistencies
		if fps, ok := metadata["fps"].(float64); ok {
			// Non-standard frame rates can indicate synthesis
			standardFPS := []float64{23.976, 24, 25, 29.97, 30, 50, 59.94, 60}
			isStandard := false
			for _, std := range standardFPS {
				if math.Abs(fps-std) < 0.1 {
					isStandard = true
					break
				}
			}
			if !isStandard && fps > 0 {
				result.Score += 0.10
				result.Indicators = append(result.Indicators, fmt.Sprintf("non-standard frame rate: %.2f", fps))
			}
		}
	}

	if result.Score > 1.0 {
		result.Score = 1.0
	}
	return result
}

// frameDifference computes the mean absolute difference between two frames.
func frameDifference(a, b []byte) float64 {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	if minLen == 0 {
		return 0
	}

	totalDiff := 0.0
	for i := 0; i < minLen; i++ {
		totalDiff += math.Abs(float64(a[i]) - float64(b[i]))
	}
	return totalDiff / float64(minLen)
}

// ---------------------------------------------------------------------------
// Event Handlers
// ---------------------------------------------------------------------------

func (s *Shield) handleAudioEvent(event *core.SecurityEvent) {
	callerID := getStringDetail(event, "caller_id")
	claimedIdentity := getStringDetail(event, "claimed_identity")

	// Run heuristic audio analysis on raw data
	audioResult := s.audioAnal.Analyze(event.RawData)

	// Also factor in metadata-based checks
	metaScore := 0.0
	sampleRate := getFloatDetail(event, "sample_rate")
	if sampleRate > 0 && sampleRate != 8000 && sampleRate != 16000 && sampleRate != 22050 && sampleRate != 44100 && sampleRate != 48000 {
		metaScore += 0.15
		audioResult.Indicators = append(audioResult.Indicators, fmt.Sprintf("unusual sample rate: %.0f Hz", sampleRate))
	}

	// Check if caller claims to be a known identity but calling from unknown number
	if claimedIdentity != "" {
		pattern := s.commTracker.GetPattern(claimedIdentity)
		if pattern != nil && callerID != "" && callerID != pattern.UsualCallerID {
			metaScore += 0.25
			audioResult.Indicators = append(audioResult.Indicators, "caller ID mismatch for claimed identity")
		}
	}

	totalScore := audioResult.Score + metaScore
	if totalScore > 1.0 {
		totalScore = 1.0
	}

	if totalScore >= 0.4 {
		severity := core.SeverityMedium
		if totalScore >= 0.7 {
			severity = core.SeverityCritical
		} else if totalScore >= 0.5 {
			severity = core.SeverityHigh
		}
		s.raiseAlert(event, severity,
			"Potential Deepfake Audio Detected",
			fmt.Sprintf("Audio from %s (claiming to be %s) has synthetic indicators (score: %.2f). Indicators: %s",
				callerID, claimedIdentity, totalScore, strings.Join(audioResult.Indicators, "; ")),
			"deepfake_audio")
	}
}

func (s *Shield) handleVideoEvent(event *core.SecurityEvent) {
	// Extract frames from event details if provided
	var frames [][]byte
	if event.RawData != nil && len(event.RawData) > 0 {
		// If raw data is a single frame, wrap it
		frames = [][]byte{event.RawData}
	}
	if frameData, ok := event.Details["frames"].([]interface{}); ok {
		for _, f := range frameData {
			if bs, ok := f.([]byte); ok {
				frames = append(frames, bs)
			}
		}
	}

	videoResult := s.videoAnal.Analyze(frames, event.Details)

	// Additional metadata checks
	claimedIdentity := getStringDetail(event, "claimed_identity")
	if claimedIdentity != "" {
		pattern := s.commTracker.GetPattern(claimedIdentity)
		if pattern != nil {
			channel := getStringDetail(event, "channel")
			if channel != "" && channel != pattern.UsualChannel {
				videoResult.Score += 0.15
				videoResult.Indicators = append(videoResult.Indicators, "unusual communication channel for claimed identity")
			}
		}
	}

	if videoResult.Score > 1.0 {
		videoResult.Score = 1.0
	}

	if videoResult.Score >= 0.4 {
		severity := core.SeverityMedium
		if videoResult.Score >= 0.7 {
			severity = core.SeverityCritical
		} else if videoResult.Score >= 0.5 {
			severity = core.SeverityHigh
		}
		s.raiseAlert(event, severity,
			"Potential Deepfake Video Detected",
			fmt.Sprintf("Video content has synthetic indicators (score: %.2f). Indicators: %s",
				videoResult.Score, strings.Join(videoResult.Indicators, "; ")),
			"deepfake_video")
	}
}

func (s *Shield) handleCommunicationEvent(event *core.SecurityEvent) {
	sender := getStringDetail(event, "sender")
	subject := getStringDetail(event, "subject")
	body := getStringDetail(event, "body")
	domain := getStringDetail(event, "sender_domain")
	headers := getStringDetail(event, "headers")

	if sender == "" && body == "" {
		return
	}

	// AI phishing detection
	phishScore := s.phishDet.Analyze(sender, subject, body, headers)
	if phishScore.IsPhishing {
		severity := core.SeverityHigh
		if phishScore.Score >= 0.8 {
			severity = core.SeverityCritical
		}
		s.raiseAlert(event, severity,
			"AI-Generated Phishing Detected",
			fmt.Sprintf("Email from %s flagged as AI-generated phishing (score: %.2f). Indicators: %s",
				sender, phishScore.Score, strings.Join(phishScore.Indicators, ", ")),
			"ai_phishing")
	}

	// Domain spoofing check
	if domain != "" {
		if spoof := s.domainCheck.Check(domain); spoof != "" {
			s.raiseAlert(event, core.SeverityHigh,
				"Domain Spoofing Detected",
				fmt.Sprintf("Sender domain %q appears to spoof legitimate domain %q using homoglyph or similar techniques.",
					domain, spoof),
				"domain_spoof")
		}
	}

	// Track communication patterns
	if sender != "" {
		s.commTracker.RecordCommunication(sender, event.SourceIP)
	}
}

func (s *Shield) handleHighValueRequest(event *core.SecurityEvent) {
	requester := getStringDetail(event, "requester")
	requestType := getStringDetail(event, "request_type")
	amount := getFloatDetail(event, "amount")
	urgency := getStringDetail(event, "urgency")
	channel := getStringDetail(event, "channel")

	riskScore := 0.0

	if urgency == "high" || urgency == "critical" || urgency == "immediate" {
		riskScore += 0.3
	}

	if amount > 10000 {
		riskScore += 0.2
	}
	if amount > 100000 {
		riskScore += 0.2
	}

	pattern := s.commTracker.GetPattern(requester)
	if pattern != nil {
		if !pattern.TypicalRequestTypes[requestType] {
			riskScore += 0.2
		}
		if channel != "" && channel != pattern.UsualChannel {
			riskScore += 0.2
		}
	} else {
		riskScore += 0.3
	}

	if riskScore >= 0.5 {
		severity := core.SeverityHigh
		if riskScore >= 0.7 {
			severity = core.SeverityCritical
		}
		s.raiseAlert(event, severity,
			"Suspicious High-Value Request",
			fmt.Sprintf("Request from %s for %s (amount: $%.2f) has BEC/deepfake risk indicators (score: %.2f). Verify identity through a separate channel.",
				requester, requestType, amount, riskScore),
			"suspicious_request")
	}
}

func (s *Shield) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.Details["original_event_id"] = event.ID

	if s.bus != nil {
		_ = s.bus.PublishEvent(newEvent)
	}

	alert := core.NewAlert(newEvent, title, description)
	alert.Mitigations = []string{
		"Verify the identity through a separate, trusted communication channel",
		"Never approve financial transactions based solely on voice/video requests",
		"Implement multi-person approval for high-value transactions",
		"Check email headers and sender authentication (SPF, DKIM, DMARC)",
		"Report suspected deepfake attempts to your security team",
	}
	if s.pipeline != nil {
		s.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// Communication Pattern Tracker
// ---------------------------------------------------------------------------

// CommunicationTracker tracks communication patterns per identity.
type CommunicationTracker struct {
	mu       sync.RWMutex
	patterns map[string]*CommPattern
}

type CommPattern struct {
	Identity            string
	UsualCallerID       string
	UsualChannel        string
	UsualIPs            map[string]bool
	TypicalRequestTypes map[string]bool
	LastSeen            time.Time
	MessageCount        int
}

func NewCommunicationTracker() *CommunicationTracker {
	return &CommunicationTracker{patterns: make(map[string]*CommPattern)}
}

func (ct *CommunicationTracker) RecordCommunication(identity, ip string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	p, exists := ct.patterns[identity]
	if !exists {
		p = &CommPattern{
			Identity:            identity,
			UsualIPs:            make(map[string]bool),
			TypicalRequestTypes: make(map[string]bool),
		}
		ct.patterns[identity] = p
	}
	if ip != "" {
		p.UsualIPs[ip] = true
	}
	p.LastSeen = time.Now()
	p.MessageCount++
}

func (ct *CommunicationTracker) GetPattern(identity string) *CommPattern {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return ct.patterns[identity]
}

func (ct *CommunicationTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ct.mu.Lock()
			cutoff := time.Now().Add(-30 * 24 * time.Hour)
			for id, p := range ct.patterns {
				if p.LastSeen.Before(cutoff) {
					delete(ct.patterns, id)
				}
			}
			ct.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// AI Phishing Detector (regex-based, no ML)
// ---------------------------------------------------------------------------

// AIPhishingDetector analyzes emails for AI-generated phishing indicators.
type AIPhishingDetector struct {
	urgencyPatterns *regexp.Regexp
	impersonation   *regexp.Regexp
	actionPatterns  *regexp.Regexp
	threatPatterns  *regexp.Regexp
}

type PhishingScore struct {
	Score      float64
	IsPhishing bool
	Indicators []string
}

func NewAIPhishingDetector() *AIPhishingDetector {
	return &AIPhishingDetector{
		urgencyPatterns: regexp.MustCompile(`(?i)(urgent|immediate\s+action|act\s+now|expires?\s+today|within\s+\d+\s+hours?|time.?sensitive|asap|right\s+away|don'?t\s+delay)`),
		impersonation:   regexp.MustCompile(`(?i)(ceo|cfo|cto|chief|director|president|vice\s+president|board\s+member|it\s+department|helpdesk|support\s+team|security\s+team)`),
		actionPatterns:  regexp.MustCompile(`(?i)(click\s+(here|this\s+link|below)|download\s+the\s+attachment|verify\s+your\s+(account|identity|password)|update\s+your\s+(payment|billing)|confirm\s+your\s+(details|information)|wire\s+transfer|send\s+funds)`),
		threatPatterns:  regexp.MustCompile(`(?i)(account\s+(will\s+be\s+)?(suspended|terminated|locked|closed)|legal\s+action|unauthorized\s+access\s+detected|security\s+breach|compromised|violation)`),
	}
}

func (d *AIPhishingDetector) Analyze(sender, subject, body, headers string) PhishingScore {
	result := PhishingScore{}
	combined := subject + " " + body

	if d.urgencyPatterns.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "urgency language")
	}

	if d.impersonation.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "executive impersonation")
	}

	if d.actionPatterns.MatchString(combined) {
		result.Score += 0.25
		result.Indicators = append(result.Indicators, "suspicious call-to-action")
	}

	if d.threatPatterns.MatchString(combined) {
		result.Score += 0.2
		result.Indicators = append(result.Indicators, "threat/fear language")
	}

	// Check for mismatched sender display name vs actual address
	if sender != "" && strings.Contains(sender, "<") {
		parts := strings.SplitN(sender, "<", 2)
		if len(parts) == 2 {
			displayName := strings.ToLower(strings.TrimSpace(parts[0]))
			if d.impersonation.MatchString(displayName) {
				result.Score += 0.15
				result.Indicators = append(result.Indicators, "display name impersonation")
			}
		}
	}

	// Header analysis
	if headers != "" {
		headerLower := strings.ToLower(headers)
		if !strings.Contains(headerLower, "dkim=pass") {
			result.Score += 0.1
			result.Indicators = append(result.Indicators, "missing DKIM")
		}
		if !strings.Contains(headerLower, "spf=pass") {
			result.Score += 0.1
			result.Indicators = append(result.Indicators, "missing SPF")
		}
		if strings.Contains(headerLower, "dmarc=fail") {
			result.Score += 0.2
			result.Indicators = append(result.Indicators, "DMARC failure")
		}
	}

	result.Score = math.Min(result.Score, 1.0)
	result.IsPhishing = result.Score >= 0.5

	return result
}

// ---------------------------------------------------------------------------
// Domain Spoof Checker (homoglyph detection)
// ---------------------------------------------------------------------------

// DomainSpoofChecker detects homoglyph and similar domain spoofing.
type DomainSpoofChecker struct {
	trustedDomains []string
	homoglyphs     map[rune]rune
}

func NewDomainSpoofChecker() *DomainSpoofChecker {
	return &DomainSpoofChecker{
		trustedDomains: []string{
			"google.com", "microsoft.com", "apple.com", "amazon.com",
			"github.com", "gitlab.com", "slack.com", "zoom.us",
			"dropbox.com", "salesforce.com", "oracle.com", "adobe.com",
			"paypal.com", "stripe.com", "twilio.com",
		},
		homoglyphs: map[rune]rune{
			'\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
			'\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
			'\u0501': 'd', '\u050D': 'n',
		},
	}
}

func (dc *DomainSpoofChecker) Check(domain string) string {
	normalized := dc.normalizeHomoglyphs(strings.ToLower(domain))

	for _, trusted := range dc.trustedDomains {
		if domain == trusted {
			continue
		}
		if normalized == trusted && domain != trusted {
			return trusted
		}
		if levenshtein(normalized, trusted) == 1 {
			return trusted
		}
	}
	return ""
}

func (dc *DomainSpoofChecker) normalizeHomoglyphs(s string) string {
	var result []rune
	for _, r := range s {
		if replacement, ok := dc.homoglyphs[r]; ok {
			result = append(result, replacement)
		} else {
			result = append(result, r)
		}
	}
	return string(result)
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = minInt(matrix[i-1][j]+1, minInt(matrix[i][j-1]+1, matrix[i-1][j-1]+cost))
		}
	}
	return matrix[la][lb]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func getFloatDetail(event *core.SecurityEvent, key string) float64 {
	if event.Details == nil {
		return 0
	}
	switch v := event.Details[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return 0
}
