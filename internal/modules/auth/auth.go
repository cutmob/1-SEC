package auth

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
)

const ModuleName = "auth_fortress"

// Fortress is the Auth Fortress module providing brute force detection,
// credential stuffing, session theft, impossible travel, MFA bypass,
// password spraying, OAuth token abuse, and consent phishing detection.
type Fortress struct {
	logger       zerolog.Logger
	bus          *core.EventBus
	pipeline     *core.AlertPipeline
	cfg          *core.Config
	ctx          context.Context
	cancel       context.CancelFunc
	loginTracker *LoginTracker
	sessionMon   *SessionMonitor
	oauthMon     *OAuthMonitor
	sprayDet     *PasswordSprayDetector
}

func New() *Fortress { return &Fortress{} }

func (f *Fortress) Name() string { return ModuleName }
func (f *Fortress) Description() string {
	return "Brute force, credential stuffing, session theft, impossible travel, MFA bypass, password spraying, OAuth token abuse, and consent phishing detection"
}

func (f *Fortress) Start(ctx context.Context, bus *core.EventBus, pipeline *core.AlertPipeline, cfg *core.Config) error {
	f.ctx, f.cancel = context.WithCancel(ctx)
	f.bus = bus
	f.pipeline = pipeline
	f.cfg = cfg
	f.logger = zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Str("module", ModuleName).Logger()

	settings := cfg.GetModuleSettings(ModuleName)
	maxFailures := getIntSetting(settings, "max_failures_per_minute", 10)
	lockoutDuration := getIntSetting(settings, "lockout_duration_seconds", 300)
	stuffingThreshold := getIntSetting(settings, "stuffing_threshold", 50)

	f.loginTracker = NewLoginTracker(maxFailures, stuffingThreshold, time.Duration(lockoutDuration)*time.Second)
	f.sessionMon = NewSessionMonitor()
	f.oauthMon = NewOAuthMonitor()
	f.sprayDet = NewPasswordSprayDetector()

	go f.loginTracker.CleanupLoop(f.ctx)
	go f.sessionMon.CleanupLoop(f.ctx)
	go f.oauthMon.CleanupLoop(f.ctx)
	go f.sprayDet.CleanupLoop(f.ctx)

	f.logger.Info().
		Int("max_failures", maxFailures).
		Int("lockout_sec", lockoutDuration).
		Msg("auth fortress started")
	return nil
}

func (f *Fortress) Stop() error {
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func (f *Fortress) HandleEvent(event *core.SecurityEvent) error {
	switch event.Type {
	case "login_attempt", "auth_attempt":
		f.handleLoginAttempt(event)
	case "login_success", "auth_success":
		f.handleLoginSuccess(event)
	case "login_failure", "auth_failure":
		f.handleLoginFailure(event)
	case "session_activity":
		f.handleSessionActivity(event)
	case "mfa_attempt":
		f.handleMFAAttempt(event)
	case "oauth_grant", "oauth_consent", "oauth_token":
		f.handleOAuthEvent(event)
	case "token_usage", "api_key_usage":
		f.handleTokenUsage(event)
	case "password_spray", "distributed_auth":
		f.handlePasswordSpray(event)
	}
	return nil
}

func (f *Fortress) handleLoginFailure(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")

	// Also feed into spray detector
	f.sprayDet.RecordFailure(ip, username)
	if spray := f.sprayDet.Check(); spray.Detected {
		f.raiseAlert(event, core.SeverityCritical,
			"Password Spraying Attack Detected",
			fmt.Sprintf("Distributed password spray detected: %d unique IPs targeting %d accounts "+
				"with %d common passwords in %s. This is a coordinated low-and-slow attack "+
				"designed to evade per-IP lockout. MITRE ATT&CK T1110.003.",
				spray.UniqueIPs, spray.UniqueUsers, spray.UniquePasswords, spray.TimeWindow),
			"password_spray")
	}

	result := f.loginTracker.RecordFailure(ip, username)

	if result.BruteForce {
		f.raiseAlert(event, core.SeverityHigh,
			"Brute Force Attack Detected",
			fmt.Sprintf("IP %s has %d failed login attempts in the last minute for user %q. Account locked for %s.",
				ip, result.FailureCount, username, f.loginTracker.lockoutDuration),
			"brute_force")
	}

	if result.CredentialStuffing {
		f.raiseAlert(event, core.SeverityCritical,
			"Credential Stuffing Attack Detected",
			fmt.Sprintf("IP %s is attempting logins against %d different usernames. This indicates a credential stuffing attack.",
				ip, result.UniqueUsers),
			"credential_stuffing")
	}
}

func (f *Fortress) handleLoginSuccess(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	sessionID := getStringDetail(event, "session_id")

	if f.loginTracker.WasRecentlyBlocked(ip) {
		f.raiseAlert(event, core.SeverityHigh,
			"Successful Login After Brute Force",
			fmt.Sprintf("IP %s successfully logged in as %q after previous brute force attempts. Possible credential compromise.",
				ip, username),
			"post_bruteforce_login")
	}

	if sessionID != "" {
		country := getStringDetail(event, "country")
		if country == "" {
			country = getStringDetail(event, "country_code")
		}
		f.sessionMon.RegisterSession(sessionID, username, ip, country, event.UserAgent)
	}

	f.loginTracker.ClearFailures(ip, username)
}

func (f *Fortress) handleLoginAttempt(event *core.SecurityEvent) {
	ip := event.SourceIP
	if f.loginTracker.IsLockedOut(ip) {
		f.raiseAlert(event, core.SeverityMedium,
			"Login Attempt During Lockout",
			fmt.Sprintf("IP %s attempted login while locked out", ip),
			"lockout_violation")
	}
}

func (f *Fortress) handleSessionActivity(event *core.SecurityEvent) {
	sessionID := getStringDetail(event, "session_id")
	if sessionID == "" {
		return
	}

	currentIP := event.SourceIP
	currentUA := event.UserAgent
	currentCountry := getStringDetail(event, "country")
	if currentCountry == "" {
		currentCountry = getStringDetail(event, "country_code")
	}

	anomaly := f.sessionMon.CheckAnomaly(sessionID, currentIP, currentCountry, currentUA)

	if anomaly.IPChanged {
		f.raiseAlert(event, core.SeverityHigh,
			"Session Hijacking Suspected",
			fmt.Sprintf("Session %s changed IP from %s to %s. Possible session theft via cookie/token hijacking.",
				truncate(sessionID, 16), anomaly.OriginalIP, currentIP),
			"session_hijack")
	}

	if anomaly.UAChanged {
		f.raiseAlert(event, core.SeverityMedium,
			"Session User-Agent Changed",
			fmt.Sprintf("Session %s user-agent changed. Original: %s, Current: %s",
				truncate(sessionID, 16), truncate(anomaly.OriginalUA, 50), truncate(currentUA, 50)),
			"session_ua_change")
	}

	if anomaly.ImpossibleTravel {
		f.raiseAlert(event, core.SeverityCritical,
			"Impossible Travel Detected",
			fmt.Sprintf("Session %s accessed from %s and %s within %s. Geographic distance makes this physically impossible.",
				truncate(sessionID, 16), anomaly.OriginalIP, currentIP, anomaly.TimeDelta.String()),
			"impossible_travel")
	}
}

func (f *Fortress) handleMFAAttempt(event *core.SecurityEvent) {
	ip := event.SourceIP
	success := getStringDetail(event, "success") == "true"
	method := getStringDetail(event, "method")

	if !success {
		failures := f.loginTracker.RecordMFAFailure(ip)
		if failures > 5 {
			f.raiseAlert(event, core.SeverityHigh,
				"MFA Bypass Attempt",
				fmt.Sprintf("IP %s has %d failed MFA attempts using method %q. Possible MFA bypass attack.",
					ip, failures, method),
				"mfa_bypass")
		}
		// MFA fatigue detection: rapid repeated push notifications
		if method == "push" && failures > 10 {
			f.raiseAlert(event, core.SeverityCritical,
				"MFA Fatigue Attack Detected",
				fmt.Sprintf("IP %s sent %d push MFA requests. Attacker is bombarding user with "+
					"push notifications hoping for accidental approval. MITRE ATT&CK T1621.",
					ip, failures),
				"mfa_fatigue")
		}
	}
}

// handleOAuthEvent detects OAuth token abuse, consent phishing, and token theft.
func (f *Fortress) handleOAuthEvent(event *core.SecurityEvent) {
	ip := event.SourceIP
	appID := getStringDetail(event, "app_id")
	appName := getStringDetail(event, "app_name")
	scopes := getStringDetail(event, "scopes")
	user := getStringDetail(event, "username")
	grantType := getStringDetail(event, "grant_type")
	redirectURI := getStringDetail(event, "redirect_uri")

	result := f.oauthMon.Analyze(ip, appID, appName, scopes, user, grantType, redirectURI)

	if result.ConsentPhishing {
		f.raiseAlert(event, core.SeverityCritical,
			"OAuth Consent Phishing Detected",
			fmt.Sprintf("Suspicious OAuth consent request from app %q (ID: %s) to user %q. "+
				"Requesting excessive scopes: %s. Redirect URI: %s. "+
				"This may be a malicious app tricking users into granting access. MITRE ATT&CK T1528.",
				appName, appID, user, scopes, redirectURI),
			"consent_phishing")
	}

	if result.TokenAbuse {
		f.raiseAlert(event, core.SeverityHigh,
			"OAuth Token Abuse Detected",
			fmt.Sprintf("App %q (ID: %s) is abusing OAuth tokens. %s. "+
				"Token used from %s. MITRE ATT&CK T1528.",
				appName, appID, result.Reason, ip),
			"oauth_token_abuse")
	}

	if result.ExcessiveScopes {
		f.raiseAlert(event, core.SeverityMedium,
			"Excessive OAuth Scope Request",
			fmt.Sprintf("App %q requesting broad OAuth scopes: %s for user %q. "+
				"Review whether this app needs this level of access.",
				appName, scopes, user),
			"excessive_oauth_scopes")
	}
}

// handleTokenUsage detects stolen token replay and API key abuse.
func (f *Fortress) handleTokenUsage(event *core.SecurityEvent) {
	tokenID := getStringDetail(event, "token_id")
	ip := event.SourceIP
	user := getStringDetail(event, "username")
	action := getStringDetail(event, "action")

	if tokenID == "" {
		return
	}

	result := f.oauthMon.TrackTokenUsage(tokenID, ip, user, action)

	if result.MultiIPUsage {
		f.raiseAlert(event, core.SeverityCritical,
			"Stolen Token Detected",
			fmt.Sprintf("Token %s for user %q is being used from %d different IPs in %s. "+
				"Original IP: %s, current: %s. Token has likely been stolen. MITRE ATT&CK T1528.",
				truncate(tokenID, 16), user, result.IPCount, result.TimeWindow,
				result.OriginalIP, ip),
			"stolen_token")
	}

	if result.AnomalousAction {
		f.raiseAlert(event, core.SeverityHigh,
			"Anomalous Token Activity",
			fmt.Sprintf("Token %s for user %q performing unusual action %q from %s. "+
				"This action has not been seen from this token before.",
				truncate(tokenID, 16), user, action, ip),
			"anomalous_token_activity")
	}
}

// handlePasswordSpray handles explicit password spray events from external detectors.
func (f *Fortress) handlePasswordSpray(event *core.SecurityEvent) {
	ip := event.SourceIP
	username := getStringDetail(event, "username")
	f.sprayDet.RecordFailure(ip, username)
}

func (f *Fortress) raiseAlert(event *core.SecurityEvent, severity core.Severity, title, description, alertType string) {
	newEvent := core.NewSecurityEvent(ModuleName, alertType, severity, description)
	newEvent.SourceIP = event.SourceIP
	newEvent.UserAgent = event.UserAgent
	newEvent.Details["original_event_id"] = event.ID

	if f.bus != nil {
		_ = f.bus.PublishEvent(newEvent)
	}
	alert := core.NewAlert(newEvent, title, description)
	if f.pipeline != nil {
		f.pipeline.Process(alert)
	}
}

// ---------------------------------------------------------------------------
// LoginTracker — brute force and credential stuffing detection
// ---------------------------------------------------------------------------

type LoginTracker struct {
	mu                sync.RWMutex
	failures          map[string]*failureRecord
	userFailures      map[string]*failureRecord
	mfaFailures       map[string]int
	lockouts          map[string]time.Time
	maxPerMinute      int
	stuffingThreshold int
	lockoutDuration   time.Duration
}

type failureRecord struct {
	count       int
	uniqueUsers map[string]bool
	window      time.Time
	lastSeen    time.Time
}

type LoginResult struct {
	BruteForce         bool
	CredentialStuffing bool
	FailureCount       int
	UniqueUsers        int
}

func NewLoginTracker(maxPerMinute, stuffingThreshold int, lockoutDuration time.Duration) *LoginTracker {
	return &LoginTracker{
		failures:          make(map[string]*failureRecord),
		userFailures:      make(map[string]*failureRecord),
		mfaFailures:       make(map[string]int),
		lockouts:          make(map[string]time.Time),
		maxPerMinute:      maxPerMinute,
		stuffingThreshold: stuffingThreshold,
		lockoutDuration:   lockoutDuration,
	}
}

func (lt *LoginTracker) RecordFailure(ip, username string) LoginResult {
	lt.mu.Lock()
	defer lt.mu.Unlock()

	now := time.Now()
	result := LoginResult{}

	rec, exists := lt.failures[ip]
	if !exists || now.Sub(rec.window) > time.Minute {
		rec = &failureRecord{uniqueUsers: make(map[string]bool), window: now}
		lt.failures[ip] = rec
	}

	rec.count++
	rec.lastSeen = now
	if username != "" {
		rec.uniqueUsers[username] = true
	}

	result.FailureCount = rec.count
	result.UniqueUsers = len(rec.uniqueUsers)

	if rec.count >= lt.maxPerMinute {
		result.BruteForce = true
		lt.lockouts[ip] = now.Add(lt.lockoutDuration)
	}
	if len(rec.uniqueUsers) >= lt.stuffingThreshold {
		result.CredentialStuffing = true
	}
	return result
}

func (lt *LoginTracker) RecordMFAFailure(ip string) int {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	lt.mfaFailures[ip]++
	return lt.mfaFailures[ip]
}

func (lt *LoginTracker) IsLockedOut(ip string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	lockoutEnd, exists := lt.lockouts[ip]
	return exists && time.Now().Before(lockoutEnd)
}

func (lt *LoginTracker) WasRecentlyBlocked(ip string) bool {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	rec, exists := lt.failures[ip]
	if !exists {
		return false
	}
	return rec.count >= lt.maxPerMinute && time.Since(rec.lastSeen) < 10*time.Minute
}

func (lt *LoginTracker) ClearFailures(ip, username string) {
	lt.mu.Lock()
	defer lt.mu.Unlock()
	delete(lt.failures, ip)
	delete(lt.mfaFailures, ip)
}

func (lt *LoginTracker) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			lt.mu.Lock()
			cutoff := time.Now().Add(-30 * time.Minute)
			for ip, rec := range lt.failures {
				if rec.lastSeen.Before(cutoff) {
					delete(lt.failures, ip)
				}
			}
			for ip, end := range lt.lockouts {
				if time.Now().After(end) {
					delete(lt.lockouts, ip)
				}
			}
			lt.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// SessionMonitor — session hijacking and impossible travel detection
// ---------------------------------------------------------------------------

type SessionMonitor struct {
	mu       sync.RWMutex
	sessions map[string]*sessionRecord
}

type sessionRecord struct {
	username  string
	ip        string
	country   string
	userAgent string
	created   time.Time
	lastSeen  time.Time
}

type SessionAnomaly struct {
	IPChanged        bool
	UAChanged        bool
	ImpossibleTravel bool
	OriginalIP       string
	OriginalUA       string
	TimeDelta        time.Duration
}

func NewSessionMonitor() *SessionMonitor {
	return &SessionMonitor{sessions: make(map[string]*sessionRecord)}
}

func (sm *SessionMonitor) RegisterSession(sessionID, username, ip, country, userAgent string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[sessionID] = &sessionRecord{
		username: username, ip: ip, country: country,
		userAgent: userAgent, created: time.Now(), lastSeen: time.Now(),
	}
}

func (sm *SessionMonitor) CheckAnomaly(sessionID, currentIP, currentCountry, currentUA string) SessionAnomaly {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	anomaly := SessionAnomaly{}
	rec, exists := sm.sessions[sessionID]
	if !exists {
		return anomaly
	}

	timeDelta := time.Since(rec.lastSeen)
	anomaly.OriginalIP = rec.ip
	anomaly.OriginalUA = rec.userAgent
	anomaly.TimeDelta = timeDelta

	if currentIP != "" && rec.ip != "" && currentIP != rec.ip {
		anomaly.IPChanged = true
		prevCountry := rec.country
		if prevCountry != "" && currentCountry != "" && prevCountry != currentCountry {
			prevLat, prevLon, prevOk := countryCentroid(prevCountry)
			curLat, curLon, curOk := countryCentroid(currentCountry)
			if prevOk && curOk {
				distKm := haversineDistance(prevLat, prevLon, curLat, curLon)
				maxTravelKm := timeDelta.Hours() * 1000
				if distKm > maxTravelKm && distKm > 500 {
					anomaly.ImpossibleTravel = true
				}
			} else if timeDelta < 5*time.Minute {
				anomaly.ImpossibleTravel = true
			}
		} else if prevCountry == "" || currentCountry == "" {
			if timeDelta < 5*time.Minute {
				anomaly.ImpossibleTravel = true
			}
		}
	}

	if currentUA != "" && rec.userAgent != "" && currentUA != rec.userAgent {
		anomaly.UAChanged = true
	}

	rec.ip = currentIP
	rec.userAgent = currentUA
	rec.lastSeen = time.Now()
	if currentCountry != "" {
		rec.country = currentCountry
	}
	return anomaly
}

func (sm *SessionMonitor) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.mu.Lock()
			cutoff := time.Now().Add(-24 * time.Hour)
			for id, rec := range sm.sessions {
				if rec.lastSeen.Before(cutoff) {
					delete(sm.sessions, id)
				}
			}
			sm.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// OAuthMonitor — OAuth token abuse, consent phishing, token theft detection
// ---------------------------------------------------------------------------

type OAuthMonitor struct {
	mu          sync.Mutex
	appGrants   map[string]*oauthAppProfile // key: appID
	tokenUsage  map[string]*tokenProfile    // key: tokenID
}

type oauthAppProfile struct {
	grantCount    int
	uniqueUsers   map[string]bool
	scopes        map[string]bool
	redirectURIs  map[string]bool
	firstSeen     time.Time
	lastSeen      time.Time
}

type tokenProfile struct {
	user       string
	ips        map[string]time.Time
	actions    map[string]bool
	firstIP    string
	firstSeen  time.Time
	lastSeen   time.Time
}

type OAuthResult struct {
	ConsentPhishing bool
	TokenAbuse      bool
	ExcessiveScopes bool
	Reason          string
}

type TokenUsageResult struct {
	MultiIPUsage    bool
	AnomalousAction bool
	IPCount         int
	OriginalIP      string
	TimeWindow      string
}

func NewOAuthMonitor() *OAuthMonitor {
	return &OAuthMonitor{
		appGrants:  make(map[string]*oauthAppProfile),
		tokenUsage: make(map[string]*tokenProfile),
	}
}

func (om *OAuthMonitor) Analyze(ip, appID, appName, scopes, user, grantType, redirectURI string) OAuthResult {
	om.mu.Lock()
	defer om.mu.Unlock()

	result := OAuthResult{}
	now := time.Now()

	// Track app grants
	profile, exists := om.appGrants[appID]
	if !exists {
		profile = &oauthAppProfile{
			uniqueUsers:  make(map[string]bool),
			scopes:       make(map[string]bool),
			redirectURIs: make(map[string]bool),
			firstSeen:    now,
		}
		om.appGrants[appID] = profile
	}
	profile.grantCount++
	profile.lastSeen = now
	if user != "" {
		profile.uniqueUsers[user] = true
	}
	if redirectURI != "" {
		profile.redirectURIs[redirectURI] = true
	}
	for _, s := range strings.Split(scopes, " ") {
		s = strings.TrimSpace(s)
		if s != "" {
			profile.scopes[s] = true
		}
	}

	// Consent phishing: new app requesting dangerous scopes from many users quickly
	dangerousScopes := map[string]bool{
		"mail.read": true, "mail.readwrite": true, "mail.send": true,
		"files.readwrite.all": true, "directory.readwrite.all": true,
		"user.readwrite.all": true, "sites.readwrite.all": true,
		"mailboxsettings.readwrite": true, "contacts.readwrite": true,
		"calendars.readwrite": true, "offline_access": true,
	}

	dangerousCount := 0
	for s := range profile.scopes {
		if dangerousScopes[strings.ToLower(s)] {
			dangerousCount++
		}
	}

	if dangerousCount >= 3 && profile.grantCount >= 3 &&
		now.Sub(profile.firstSeen) < 1*time.Hour {
		result.ConsentPhishing = true
	}

	// Excessive scopes
	if dangerousCount >= 4 || len(profile.scopes) >= 8 {
		result.ExcessiveScopes = true
	}

	// Token abuse: rapid grants to many users
	if profile.grantCount > 20 && len(profile.uniqueUsers) > 10 &&
		now.Sub(profile.firstSeen) < 30*time.Minute {
		result.TokenAbuse = true
		result.Reason = fmt.Sprintf("Rapid OAuth grants: %d grants to %d users in %s",
			profile.grantCount, len(profile.uniqueUsers),
			now.Sub(profile.firstSeen).Round(time.Second))
	}

	return result
}

func (om *OAuthMonitor) TrackTokenUsage(tokenID, ip, user, action string) TokenUsageResult {
	om.mu.Lock()
	defer om.mu.Unlock()

	result := TokenUsageResult{}
	now := time.Now()

	profile, exists := om.tokenUsage[tokenID]
	if !exists {
		profile = &tokenProfile{
			user:      user,
			ips:       make(map[string]time.Time),
			actions:   make(map[string]bool),
			firstIP:   ip,
			firstSeen: now,
		}
		om.tokenUsage[tokenID] = profile
	}
	profile.lastSeen = now
	if ip != "" {
		profile.ips[ip] = now
	}

	// Check for anomalous action (new action not seen before)
	if action != "" {
		if len(profile.actions) > 5 && !profile.actions[action] {
			result.AnomalousAction = true
		}
		profile.actions[action] = true
	}

	// Multi-IP usage: token used from 3+ IPs
	result.IPCount = len(profile.ips)
	result.OriginalIP = profile.firstIP
	result.TimeWindow = now.Sub(profile.firstSeen).Round(time.Second).String()
	if len(profile.ips) >= 3 {
		result.MultiIPUsage = true
	}

	return result
}

func (om *OAuthMonitor) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			om.mu.Lock()
			cutoff := time.Now().Add(-1 * time.Hour)
			for id, p := range om.appGrants {
				if p.lastSeen.Before(cutoff) {
					delete(om.appGrants, id)
				}
			}
			tokenCutoff := time.Now().Add(-24 * time.Hour)
			for id, p := range om.tokenUsage {
				if p.lastSeen.Before(tokenCutoff) {
					delete(om.tokenUsage, id)
				}
			}
			om.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// PasswordSprayDetector — detects distributed low-and-slow password spraying
// ---------------------------------------------------------------------------

type PasswordSprayDetector struct {
	mu          sync.Mutex
	attempts    []sprayAttempt
	windowStart time.Time
}

type sprayAttempt struct {
	ip       string
	username string
	time     time.Time
}

type SprayResult struct {
	Detected        bool
	UniqueIPs       int
	UniqueUsers     int
	UniquePasswords int
	TimeWindow      string
}

func NewPasswordSprayDetector() *PasswordSprayDetector {
	return &PasswordSprayDetector{windowStart: time.Now()}
}

func (ps *PasswordSprayDetector) RecordFailure(ip, username string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.attempts = append(ps.attempts, sprayAttempt{ip: ip, username: username, time: time.Now()})
}

func (ps *PasswordSprayDetector) Check() SprayResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	result := SprayResult{}
	now := time.Now()

	// Only look at last 10 minutes
	cutoff := now.Add(-10 * time.Minute)
	var recent []sprayAttempt
	for _, a := range ps.attempts {
		if a.time.After(cutoff) {
			recent = append(recent, a)
		}
	}
	ps.attempts = recent

	if len(recent) < 20 {
		return result
	}

	ips := make(map[string]bool)
	users := make(map[string]bool)
	for _, a := range recent {
		ips[a.ip] = true
		users[a.username] = true
	}

	result.UniqueIPs = len(ips)
	result.UniqueUsers = len(users)
	result.UniquePasswords = 1 // We can't see passwords, but spray = 1-2 passwords across many users
	result.TimeWindow = now.Sub(ps.windowStart).Round(time.Second).String()

	// Password spray pattern: many IPs, many users, low attempts per IP
	// Typical spray: 1-2 attempts per IP across 10+ users from 5+ IPs
	if len(ips) >= 5 && len(users) >= 10 {
		avgAttemptsPerIP := float64(len(recent)) / float64(len(ips))
		if avgAttemptsPerIP <= 3 {
			result.Detected = true
		}
	}

	// Also detect single-IP spray: one IP, many users, 1 attempt each
	for ip := range ips {
		ipUsers := make(map[string]bool)
		for _, a := range recent {
			if a.ip == ip {
				ipUsers[a.username] = true
			}
		}
		if len(ipUsers) >= 20 {
			result.Detected = true
			result.UniqueUsers = len(ipUsers)
		}
	}

	return result
}

func (ps *PasswordSprayDetector) CleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ps.mu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			var kept []sprayAttempt
			for _, a := range ps.attempts {
				if a.time.After(cutoff) {
					kept = append(kept, a)
				}
			}
			ps.attempts = kept
			ps.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

func getStringDetail(event *core.SecurityEvent, key string) string {
	if event.Details == nil {
		return ""
	}
	if val, ok := event.Details[key].(string); ok {
		return val
	}
	return ""
}

func getIntSetting(settings map[string]interface{}, key string, defaultVal int) int {
	if val, ok := settings[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		}
	}
	return defaultVal
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 6371.0
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1*math.Pi/180)*math.Cos(lat2*math.Pi/180)*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return R * c
}

func countryCentroid(code string) (lat, lon float64, ok bool) {
	centroids := map[string][2]float64{
		"US": {39.8, -98.5}, "CN": {35.9, 104.2}, "IN": {20.6, 78.9},
		"BR": {-14.2, -51.9}, "RU": {61.5, 105.3}, "JP": {36.2, 138.3},
		"DE": {51.2, 10.5}, "GB": {55.4, -3.4}, "FR": {46.2, 2.2},
		"KR": {35.9, 127.8}, "CA": {56.1, -106.3}, "IT": {41.9, 12.6},
		"AU": {-25.3, 133.8}, "ES": {40.5, -3.7}, "MX": {23.6, -102.6},
		"ID": {-0.8, 113.9}, "NL": {52.1, 5.3}, "TR": {39.0, 35.2},
		"SA": {23.9, 45.1}, "CH": {46.8, 8.2}, "PL": {51.9, 19.1},
		"SE": {60.1, 18.6}, "BE": {50.5, 4.5}, "TH": {15.9, 100.9},
		"AT": {47.5, 14.6}, "NO": {60.5, 8.5}, "IL": {31.0, 34.9},
		"NG": {9.1, 8.7}, "ZA": {-30.6, 22.9}, "AR": {-38.4, -63.6},
		"EG": {26.8, 30.8}, "PH": {12.9, 121.8}, "MY": {4.2, 101.9},
		"SG": {1.4, 103.8}, "AE": {23.4, 53.8}, "IE": {53.1, -8.2},
		"DK": {56.3, 9.5}, "FI": {61.9, 25.7}, "PT": {39.4, -8.2},
		"CZ": {49.8, 15.5}, "RO": {45.9, 25.0}, "NZ": {-40.9, 174.9},
		"CL": {-35.7, -71.5}, "CO": {4.6, -74.3}, "UA": {48.4, 31.2},
		"PK": {30.4, 69.3}, "VN": {14.1, 108.3}, "HK": {22.4, 114.1},
		"TW": {23.7, 121.0}, "BD": {23.7, 90.4}, "PE": {-9.2, -75.0},
	}
	if c, found := centroids[code]; found {
		return c[0], c[1], true
	}
	return 0, 0, false
}
