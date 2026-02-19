package injection

import (
	"regexp"

	"github.com/1sec-project/1sec/internal/core"
)

func compilePatterns() []Pattern {
	patterns := []Pattern{
		// SQL Injection patterns
		{Name: "sqli_union", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\bunion\b\s+(all\s+)?select\b)`)},
		{Name: "sqli_or_true", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\bor\b\s+[\d'"]+=\s*[\d'"]+|'\s*or\s*'[^']*'\s*=\s*'[^']*')`)},
		{Name: "sqli_comment", Category: "sqli", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)(--|#|/\*.*?\*/|;)\s*(drop|alter|delete|update|insert|create|exec|execute)\b`)},
		{Name: "sqli_stacked", Category: "sqli", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i);\s*(drop|alter|truncate|delete\s+from|update\s+\w+\s+set|insert\s+into|create|exec|execute)\b`)},
		{Name: "sqli_sleep", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay\s+')`)},
		{Name: "sqli_extract", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(extractvalue|updatexml|load_file|into\s+(out|dump)file)\s*\(`)},
		{Name: "sqli_information_schema", Category: "sqli", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(information_schema|sys\.objects|sysobjects|syscolumns|pg_catalog)`)},
		{Name: "sqli_hex_encode", Category: "sqli", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(0x[0-9a-f]{8,}|char\s*\(\s*\d+(\s*,\s*\d+)+\s*\)|concat\s*\()`)},

		// XSS patterns
		{Name: "xss_script_tag", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)<\s*script[^>]*>`)},
		{Name: "xss_event_handler", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)\bon(error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseout|dblclick|contextmenu|drag|drop)\s*=`)},
		{Name: "xss_javascript_uri", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(javascript|vbscript|data)\s*:`)},
		{Name: "xss_img_tag", Category: "xss", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)<\s*(img|iframe|embed|object|svg|math|video|audio|source)\b[^>]*(src|href|data|action)\s*=`)},
		{Name: "xss_style_expression", Category: "xss", Severity: core.SeverityMedium,
			Regex: regexp.MustCompile(`(?i)(expression\s*\(|url\s*\(\s*(javascript|data):)`)},
		{Name: "xss_dom_manipulation", Category: "xss", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(document\.(cookie|write|location|domain)|window\.(location|open)|\.innerHTML\s*=|eval\s*\()`)},

		// Command Injection patterns
		{Name: "cmdi_pipe", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(\||\|\||&&|;|` + "`" + `)\s*(cat|ls|dir|whoami|id|uname|pwd|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php)\b`)},
		{Name: "cmdi_subshell", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`\$\((cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\b`)},
		{Name: "cmdi_backtick", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile("`(cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\\b")},
		{Name: "cmdi_redirect", Category: "cmdi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(>\s*/etc/|>\s*/tmp/|<\s*/etc/passwd|/dev/(tcp|udp)/)`)},
		{Name: "cmdi_reverse_shell", Category: "cmdi", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(bash\s+-i\s+>&|nc\s+-[elp]|ncat\s+-|python\s+-c\s+.*socket|perl\s+-e\s+.*socket|ruby\s+-rsocket|php\s+-r\s+.*fsockopen)`)},

		// SSRF patterns
		{Name: "ssrf_internal_ip", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(https?://)?(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|localhost|0x7f|2130706433)`)},
		{Name: "ssrf_cloud_metadata", Category: "ssrf", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)`)},
		{Name: "ssrf_file_scheme", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(file|gopher|dict|ftp|ldap|tftp)://`)},
		{Name: "ssrf_dns_rebind", Category: "ssrf", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\.burpcollaborator\.net|\.oastify\.com|\.interact\.sh|\.requestbin\.|\.ngrok\.)`)},

		// LDAP Injection patterns
		{Name: "ldapi_wildcard", Category: "ldapi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\*\)\(&|\)\(\||\)\(!\(|%2a%29%28)`)},
		{Name: "ldapi_filter", Category: "ldapi", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\(\||\(&|\(!\s*\().*?(uid|cn|sn|mail|objectclass)\s*=`)},

		// Template Injection patterns
		{Name: "template_jinja", Category: "template", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`\{\{.*?(__|class|mro|subclasses|builtins|import|popen|system|eval|exec|getattr).*?\}\}`)},
		{Name: "template_expression", Category: "template", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(\$\{.*?(Runtime|ProcessBuilder|exec|getClass).*?\}|#\{.*?(T\(|new\s+java).*?\})`)},
		{Name: "template_freemarker", Category: "template", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(<#assign|<@|\$\{.*?\.getClass\(\))`)},
		{Name: "template_twig", Category: "template", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`\{\{.*?(system|passthru|exec|popen|file_get_contents).*?\}\}`)},

		// NoSQL Injection patterns
		{Name: "nosql_operator", Category: "nosql", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\$gt|\$lt|\$gte|\$lte|\$ne|\$nin|\$in|\$regex|\$where|\$exists|\$or|\$and|\$not|\$nor)\b`)},
		{Name: "nosql_js_exec", Category: "nosql", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(\$where\s*:\s*['"]?function|this\.\w+\s*==|db\.\w+\.(find|remove|update|drop|insert))`)},
		{Name: "nosql_json_inject", Category: "nosql", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)\{\s*['"]\$\w+['"]\s*:`)},

		// Path Traversal patterns
		{Name: "path_traversal", Category: "path", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(?i)(\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/]|\.\.%2f|%2e%2e%2f){2,}`)},
		{Name: "path_sensitive_files", Category: "path", Severity: core.SeverityCritical,
			Regex: regexp.MustCompile(`(?i)(/etc/(passwd|shadow|hosts|crontab)|/proc/self/|/windows/system32/|web\.config|\.env|\.git/config|\.htaccess|wp-config\.php)`)},
		{Name: "path_null_byte", Category: "path", Severity: core.SeverityHigh,
			Regex: regexp.MustCompile(`(%00|\\x00|\\0)`)},
	}

	return patterns
}
