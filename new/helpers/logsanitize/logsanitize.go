package logsanitize

import "regexp"

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(password|token|secret|authorization|cookie)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`(?i)(mongodb(\+srv)?://)[^\s]+`),
	regexp.MustCompile(`(?i)(email|username)\s*[:=]\s*[^\s,;]+`),
}

// Message redacts known sensitive key/value pairs and connection strings.
func Message(msg string) string {
	if msg == "" {
		return msg
	}

	sanitized := msg
	for _, re := range redactPatterns {
		sanitized = re.ReplaceAllString(sanitized, "$1=[REDACTED]")
	}

	return sanitized
}