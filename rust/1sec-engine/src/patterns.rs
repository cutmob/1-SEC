//! Pattern definitions — mirrors `injection/patterns.go` plus additional patterns
//! from other modules. These are compiled into a high-performance Aho-Corasick + regex
//! pipeline for hot-path matching.

use crate::events::Severity;

/// A raw pattern definition before compilation.
#[derive(Debug, Clone)]
pub struct PatternDef {
    pub name: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub regex: &'static str,
    /// Quick literal strings for Aho-Corasick pre-filtering.
    /// If any of these appear in the input, the full regex is tested.
    /// Empty means always test the regex (no pre-filter shortcut).
    pub literals: &'static [&'static str],
}

/// Returns all pattern definitions across all categories.
pub fn all_patterns() -> Vec<PatternDef> {
    let mut patterns = Vec::with_capacity(128);
    patterns.extend(sqli_patterns());
    patterns.extend(xss_patterns());
    patterns.extend(cmdi_patterns());
    patterns.extend(ssrf_patterns());
    patterns.extend(ldap_patterns());
    patterns.extend(template_patterns());
    patterns.extend(nosql_patterns());
    patterns.extend(path_traversal_patterns());
    patterns.extend(prompt_injection_patterns());
    patterns.extend(ransomware_patterns());
    patterns.extend(auth_patterns());
    patterns.extend(exfiltration_patterns());
    patterns
}

fn sqli_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "sqli_union",
            category: "sqli",
            severity: Severity::High,
            regex: r"(?i)(\bunion\b\s+(all\s+)?select\b)",
            literals: &["union", "UNION"],
        },
        PatternDef {
            name: "sqli_or_true",
            category: "sqli",
            severity: Severity::High,
            regex: r"(?i)(\bor\b\s+[\d'""]=\s*[\d'""]+|'\s*or\s*'[^']*'\s*=\s*'[^']*')",
            literals: &["or", "OR"],
        },
        PatternDef {
            name: "sqli_comment_ddl",
            category: "sqli",
            severity: Severity::Medium,
            regex: r"(?i)(--|#|/\*.*?\*/|;)\s*(drop|alter|delete|update|insert|create|exec|execute)\b",
            literals: &["drop", "alter", "delete", "update", "insert", "create", "exec", "DROP", "ALTER", "DELETE"],
        },
        PatternDef {
            name: "sqli_stacked",
            category: "sqli",
            severity: Severity::Critical,
            regex: r"(?i);\s*(drop|alter|truncate|delete\s+from|update\s+\w+\s+set|insert\s+into|create|exec|execute)\b",
            literals: &[";"],
        },
        PatternDef {
            name: "sqli_sleep",
            category: "sqli",
            severity: Severity::High,
            regex: r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay\s+')",
            literals: &["sleep", "benchmark", "waitfor", "SLEEP", "BENCHMARK", "WAITFOR"],
        },
        PatternDef {
            name: "sqli_extract",
            category: "sqli",
            severity: Severity::High,
            regex: r"(?i)(extractvalue|updatexml|load_file|into\s+(out|dump)file)\s*\(",
            literals: &["extractvalue", "updatexml", "load_file", "outfile", "dumpfile"],
        },
        PatternDef {
            name: "sqli_information_schema",
            category: "sqli",
            severity: Severity::Critical,
            regex: r"(?i)(information_schema|sys\.objects|sysobjects|syscolumns|pg_catalog)",
            literals: &["information_schema", "sys.objects", "sysobjects", "syscolumns", "pg_catalog"],
        },
        PatternDef {
            name: "sqli_hex_encode",
            category: "sqli",
            severity: Severity::High,
            regex: r"(?i)(0x[0-9a-f]{8,}|char\s*\(\s*\d+(\s*,\s*\d+)+\s*\)|concat\s*\()",
            literals: &["0x", "char(", "concat(", "CHAR(", "CONCAT("],
        },
    ]
}

fn xss_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "xss_script_tag",
            category: "xss",
            severity: Severity::High,
            regex: r"(?i)<\s*script[^>]*>",
            literals: &["<script", "<SCRIPT", "< script"],
        },
        PatternDef {
            name: "xss_event_handler",
            category: "xss",
            severity: Severity::High,
            regex: r"(?i)\bon(error|load|click|mouseover|focus|blur|submit|change|input|keyup|keydown|mouseout|dblclick|contextmenu|drag|drop)\s*=",
            literals: &["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur", "onsubmit"],
        },
        PatternDef {
            name: "xss_javascript_uri",
            category: "xss",
            severity: Severity::High,
            regex: r"(?i)(javascript|vbscript|data)\s*:",
            literals: &["javascript:", "vbscript:", "data:"],
        },
        PatternDef {
            name: "xss_dangerous_tags",
            category: "xss",
            severity: Severity::Medium,
            regex: r"(?i)<\s*(img|iframe|embed|object|svg|math|video|audio|source)\b[^>]*(src|href|data|action)\s*=",
            literals: &["<img", "<iframe", "<embed", "<object", "<svg", "<math", "<video"],
        },
        PatternDef {
            name: "xss_style_expression",
            category: "xss",
            severity: Severity::Medium,
            regex: r"(?i)(expression\s*\(|url\s*\(\s*(javascript|data):)",
            literals: &["expression(", "url(javascript", "url(data"],
        },
        PatternDef {
            name: "xss_dom_manipulation",
            category: "xss",
            severity: Severity::High,
            regex: r"(?i)(document\.(cookie|write|location|domain)|window\.(location|open)|\.innerHTML\s*=|eval\s*\()",
            literals: &["document.cookie", "document.write", "document.location", "window.location", "innerHTML", "eval("],
        },
    ]
}

fn cmdi_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "cmdi_pipe",
            category: "cmdi",
            severity: Severity::Critical,
            regex: r"(\||\|\||&&|;|`)\s*(cat|ls|dir|whoami|id|uname|pwd|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php)\b",
            literals: &["cat", "whoami", "uname", "wget", "curl", "bash", "powershell"],
        },
        PatternDef {
            name: "cmdi_subshell",
            category: "cmdi",
            severity: Severity::Critical,
            regex: r"\$\((cat|ls|whoami|id|uname|pwd|wget|curl|nc|bash|sh)\b",
            literals: &["$("],
        },
        PatternDef {
            name: "cmdi_redirect",
            category: "cmdi",
            severity: Severity::High,
            regex: r"(>\s*/etc/|>\s*/tmp/|<\s*/etc/passwd|/dev/(tcp|udp)/)",
            literals: &["/etc/", "/tmp/", "/dev/tcp", "/dev/udp"],
        },
        PatternDef {
            name: "cmdi_reverse_shell",
            category: "cmdi",
            severity: Severity::Critical,
            regex: r"(?i)(bash\s+-i\s+>&|nc\s+-[elp]|ncat\s+-|python\s+-c\s+.*socket|perl\s+-e\s+.*socket|ruby\s+-rsocket|php\s+-r\s+.*fsockopen)",
            literals: &["bash -i", "nc -", "ncat -", "fsockopen", "-rsocket"],
        },
    ]
}

fn ssrf_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "ssrf_internal_ip",
            category: "ssrf",
            severity: Severity::High,
            regex: r"(?i)(https?://)?(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0|localhost|0x7f|2130706433)",
            literals: &["127.", "10.", "172.", "192.168.", "0.0.0.0", "localhost", "0x7f"],
        },
        PatternDef {
            name: "ssrf_cloud_metadata",
            category: "ssrf",
            severity: Severity::Critical,
            regex: r"(?i)(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)",
            literals: &["169.254.169.254", "metadata.google.internal", "100.100.100.200"],
        },
        PatternDef {
            name: "ssrf_dangerous_scheme",
            category: "ssrf",
            severity: Severity::High,
            regex: r"(?i)(file|gopher|dict|ftp|ldap|tftp)://",
            literals: &["file://", "gopher://", "dict://", "ftp://", "ldap://", "tftp://"],
        },
        PatternDef {
            name: "ssrf_dns_rebind",
            category: "ssrf",
            severity: Severity::High,
            regex: r"(?i)(\.burpcollaborator\.net|\.oastify\.com|\.interact\.sh|\.requestbin\.|\.ngrok\.)",
            literals: &["burpcollaborator", "oastify", "interact.sh", "requestbin", "ngrok"],
        },
    ]
}

fn ldap_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "ldapi_wildcard",
            category: "ldapi",
            severity: Severity::High,
            regex: r"(?i)(\*\)\(&|\)\(\||\)\(!\(|%2a%29%28)",
            literals: &["*)(&", ")(|", ")(!(", "%2a%29%28"],
        },
        PatternDef {
            name: "ldapi_filter",
            category: "ldapi",
            severity: Severity::High,
            regex: r"(?i)(\(\||\(&|\(!\s*\().*?(uid|cn|sn|mail|objectclass)\s*=",
            literals: &["(|", "(&", "(!", "uid=", "cn=", "objectclass="],
        },
    ]
}

fn template_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "template_jinja",
            category: "template_injection",
            severity: Severity::Critical,
            regex: r"\{\{.*?(__|class|mro|subclasses|builtins|import|popen|system|eval|exec|getattr).*?\}\}",
            literals: &["{{", "__class__", "__mro__", "subclasses", "builtins", "popen"],
        },
        PatternDef {
            name: "template_expression",
            category: "template_injection",
            severity: Severity::High,
            regex: r#"(\$\{.*?(Runtime|ProcessBuilder|exec|getClass).*?\}|#\{.*?(T\(|new\s+java).*?\})"#,
            literals: &["${", "#{", "Runtime", "ProcessBuilder", "getClass"],
        },
        PatternDef {
            name: "template_freemarker",
            category: "template_injection",
            severity: Severity::Critical,
            regex: r"(?i)(<#assign|<@|\$\{.*?\.getClass\(\))",
            literals: &["<#assign", "<@", "getClass()"],
        },
    ]
}

fn nosql_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "nosql_operator",
            category: "nosql_injection",
            severity: Severity::High,
            regex: r#"(?i)(\$gt|\$lt|\$gte|\$lte|\$ne|\$nin|\$in|\$regex|\$where|\$exists|\$or|\$and|\$not|\$nor)\b"#,
            literals: &["$gt", "$lt", "$ne", "$nin", "$regex", "$where", "$exists", "$or"],
        },
        PatternDef {
            name: "nosql_js_exec",
            category: "nosql_injection",
            severity: Severity::Critical,
            regex: r#"(?i)(\$where\s*:\s*['"]?function|this\.\w+\s*==|db\.\w+\.(find|remove|update|drop|insert))"#,
            literals: &["$where", "this.", "db."],
        },
    ]
}

fn path_traversal_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "path_traversal",
            category: "path_traversal",
            severity: Severity::High,
            regex: r"(?i)(\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/]|\.\.%2f|%2e%2e%2f){2,}",
            literals: &["../", "..\\", "%2e%2e", "%252e"],
        },
        PatternDef {
            name: "path_sensitive_files",
            category: "path_traversal",
            severity: Severity::Critical,
            regex: r"(?i)(/etc/(passwd|shadow|hosts|crontab)|/proc/self/|/windows/system32/|web\.config|\.env|\.git/config|\.htaccess|wp-config\.php)",
            literals: &["/etc/passwd", "/etc/shadow", "/proc/self", "web.config", ".env", ".git/config", ".htaccess", "wp-config"],
        },
        PatternDef {
            name: "path_null_byte",
            category: "path_traversal",
            severity: Severity::High,
            regex: r"(%00|\\x00|\\0)",
            literals: &["%00", "\\x00", "\\0"],
        },
    ]
}

fn prompt_injection_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "prompt_ignore_instructions",
            category: "prompt_injection",
            severity: Severity::Critical,
            regex: r"(?i)(ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules|context)|disregard\s+(all\s+)?(previous|above|prior))",
            literals: &["ignore", "disregard", "previous instructions", "prior instructions"],
        },
        PatternDef {
            name: "prompt_role_override",
            category: "prompt_injection",
            severity: Severity::Critical,
            regex: r"(?i)(you\s+are\s+now\s+|act\s+as\s+(a\s+)?|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+you|new\s+instructions?:)",
            literals: &["you are now", "act as", "pretend to be", "new instructions"],
        },
        PatternDef {
            name: "prompt_system_leak",
            category: "prompt_injection",
            severity: Severity::High,
            regex: r"(?i)(reveal\s+(your|the)\s+(system|initial|original)\s+(prompt|instructions|message)|what\s+(are|is)\s+your\s+(system|initial)\s+(prompt|instructions)|show\s+me\s+your\s+(prompt|instructions|rules))",
            literals: &["system prompt", "initial prompt", "reveal your", "show me your"],
        },
        PatternDef {
            name: "prompt_delimiter_escape",
            category: "prompt_injection",
            severity: Severity::High,
            regex: r"(?i)(```\s*(system|assistant|user)|<\|?(system|endoftext|im_start|im_end)\|?>|\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>)",
            literals: &["```system", "<|system", "<|endoftext", "[INST]", "<<SYS>>"],
        },
        PatternDef {
            name: "prompt_encoding_bypass",
            category: "prompt_injection",
            severity: Severity::High,
            regex: r"(?i)(base64\s*decode|rot13|hex\s*decode|unicode\s*escape|translate\s+from\s+(base64|hex|rot13))",
            literals: &["base64", "rot13", "hex decode", "unicode escape"],
        },
        PatternDef {
            name: "prompt_jailbreak",
            category: "prompt_injection",
            severity: Severity::Critical,
            regex: r"(?i)(DAN\s*mode|do\s+anything\s+now|developer\s+mode\s+(enabled|output)|jailbreak|bypass\s+(safety|content|ethical)\s+(filter|restriction|guideline))",
            literals: &["DAN", "do anything now", "developer mode", "jailbreak", "bypass safety"],
        },
    ]
}

fn ransomware_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "ransomware_encryption_api",
            category: "ransomware",
            severity: Severity::Critical,
            regex: r"(?i)(CryptEncrypt|CryptGenKey|BCryptEncrypt|NCryptEncrypt|CryptoAPI|RtlEncryptMemory)",
            literals: &["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "NCryptEncrypt"],
        },
        PatternDef {
            name: "ransomware_shadow_delete",
            category: "ransomware",
            severity: Severity::Critical,
            regex: r"(?i)(vssadmin\s+(delete|resize)\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+no)",
            literals: &["vssadmin", "shadowcopy delete", "bcdedit", "recoveryenabled"],
        },
        PatternDef {
            name: "ransomware_ransom_note",
            category: "ransomware",
            severity: Severity::High,
            regex: r"(?i)(your\s+files\s+(have\s+been|are)\s+encrypted|pay\s+.*bitcoin|send\s+.*btc|decrypt\s+your\s+files|ransom\s+note)",
            literals: &["files have been encrypted", "files are encrypted", "bitcoin", "decrypt your files", "ransom"],
        },
        PatternDef {
            name: "ransomware_file_extensions",
            category: "ransomware",
            severity: Severity::High,
            regex: r"\.(locked|encrypted|crypt|cry|crypto|enc|locky|cerber|wannacry|petya|ryuk|maze|revil|conti|lockbit|blackcat|alphv)\b",
            literals: &[".locked", ".encrypted", ".crypt", ".locky", ".cerber", ".wannacry", ".lockbit", ".blackcat"],
        },
    ]
}

fn auth_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "auth_jwt_none_alg",
            category: "auth_bypass",
            severity: Severity::Critical,
            regex: r#"(?i)("alg"\s*:\s*"none"|"alg"\s*:\s*"None"|"alg"\s*:\s*"NONE"|"alg"\s*:\s*"nOnE")"#,
            literals: &["\"alg\"", "none", "None", "NONE"],
        },
        PatternDef {
            name: "auth_jwt_alg_confusion",
            category: "auth_bypass",
            severity: Severity::Critical,
            regex: r#"(?i)"alg"\s*:\s*"(HS256|HS384|HS512)"\s*.*"typ"\s*:\s*"JWT".*-----BEGIN\s*(RSA\s+)?PUBLIC\s+KEY"#,
            literals: &["HS256", "HS384", "HS512", "PUBLIC KEY"],
        },
        PatternDef {
            name: "auth_credential_stuffing",
            category: "credential_attack",
            severity: Severity::High,
            regex: r"(?i)(admin|root|administrator|superuser|sa)\s*[:/]\s*(password|admin|root|123456|qwerty|letmein|welcome|monkey|dragon)",
            literals: &["admin", "root", "password", "123456", "qwerty", "letmein"],
        },
    ]
}

fn exfiltration_patterns() -> Vec<PatternDef> {
    vec![
        PatternDef {
            name: "exfil_dns_tunnel",
            category: "data_exfiltration",
            severity: Severity::High,
            regex: r"[a-zA-Z0-9]{32,}\.(com|net|org|io|xyz|tk|ml|ga|cf)\b",
            literals: &[],  // No good literal pre-filter for this one
        },
        PatternDef {
            name: "exfil_base64_bulk",
            category: "data_exfiltration",
            severity: Severity::Medium,
            regex: r"[A-Za-z0-9+/]{100,}={0,2}",
            literals: &[],
        },
        PatternDef {
            name: "exfil_sensitive_data",
            category: "data_exfiltration",
            severity: Severity::Critical,
            regex: r"(?i)(credit.?card|social.?security|ssn|passport.?number|bank.?account|routing.?number|api.?key|secret.?key|private.?key|access.?token)",
            literals: &["credit", "social security", "ssn", "passport", "bank account", "api key", "secret key", "private key", "access token"],
        },
    ]
}
