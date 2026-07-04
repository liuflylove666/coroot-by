package rca

import "regexp"

var sensitivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^\s,;]+`),
	regexp.MustCompile(`(?i)((password|passwd|secret|token|api[_-]?key|cookie)=)[^\s,;]+`),
	regexp.MustCompile(`(?i)((password|passwd|secret|token|api[_-]?key|cookie):\s*)[^\s,;]+`),
}

func sanitizeText(s string) string {
	for _, re := range sensitivePatterns {
		s = re.ReplaceAllString(s, "${1}<redacted>")
	}
	return s
}
