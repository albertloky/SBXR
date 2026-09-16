package host

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

const RenewalRateLimited = "rate-limited"

const maxRenewalDiagnosticBytes = 32 << 10

var (
	rateLimitURNLine         = regexp.MustCompile(`(?i)^(?:acme\.messages\.Error:\s*)?urn:ietf:params:acme:error:ratelimited(?:\s|:|$)`)
	rateLimitJSONType        = regexp.MustCompile(`(?i)^\{?\s*"type"\s*:\s*"urn:ietf:params:acme:error:ratelimited"`)
	exactIdentifierRateLimit = regexp.MustCompile(`(?i)^(?:"detail"\s*:\s*")?too many certificates \([0-9]+\) already issued for this exact set of identifiers in the last [^,\r\n]+`)
	retryAfterText           = regexp.MustCompile(`(?i)retry after ([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC)(?:[^A-Za-z]|$)`)
)

type RenewalFailure struct {
	Kind       string `json:"kind"`
	RetryAfter string `json:"retry_after,omitempty"`
}

// UnmarshalJSON keeps optional diagnostics from gaining authority over the
// otherwise strict renewal receipt. Unknown fields and invalid field types are
// discarded; Safe decides whether the resulting values are recognized.
func (failure *RenewalFailure) UnmarshalJSON(data []byte) error {
	*failure = RenewalFailure{}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return nil
	}
	_ = json.Unmarshal(fields["kind"], &failure.Kind)
	_ = json.Unmarshal(fields["retry_after"], &failure.RetryAfter)
	return nil
}

// Safe returns only the recognized, canonical diagnostic fields suitable for
// persistence or display. A malformed retry time does not erase its category.
func (failure *RenewalFailure) Safe() *RenewalFailure {
	if failure == nil || failure.Kind != RenewalRateLimited {
		return nil
	}
	safe := &RenewalFailure{Kind: RenewalRateLimited}
	if retry, err := time.Parse(time.RFC3339, failure.RetryAfter); err == nil {
		safe.RetryAfter = retry.UTC().Format(time.RFC3339)
	}
	return safe
}

type boundedRenewalDiagnostic struct {
	bytes    []byte
	overflow bool
}

func (capture *boundedRenewalDiagnostic) Write(data []byte) (int, error) {
	remaining := maxRenewalDiagnosticBytes - len(capture.bytes)
	if remaining < len(data) {
		capture.overflow = true
	}
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		capture.bytes = append(capture.bytes, data[:remaining]...)
	}
	return len(data), nil
}

func (capture *boundedRenewalDiagnostic) failure() *RenewalFailure {
	if capture == nil || capture.overflow {
		return nil
	}
	return classifyRenewalFailure(string(capture.bytes))
}

func classifyRenewalFailure(stderr string) *RenewalFailure {
	recognized := false
	malformedRetry := false
	retries := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		trimmed := strings.TrimSpace(line)
		if !rateLimitURNLine.MatchString(trimmed) && !rateLimitJSONType.MatchString(trimmed) && !exactIdentifierRateLimit.MatchString(trimmed) {
			continue
		}
		recognized = true
		matches := retryAfterText.FindAllStringSubmatch(line, -1)
		if strings.Count(strings.ToLower(line), "retry after") != len(matches) {
			malformedRetry = true
		}
		for _, match := range matches {
			retry, err := time.Parse("2006-01-02 15:04:05 MST", match[1])
			if err != nil || retry.Location() != time.UTC {
				malformedRetry = true
				continue
			}
			retries[retry.UTC().Format(time.RFC3339)] = true
		}
	}
	if !recognized {
		return nil
	}
	failure := &RenewalFailure{Kind: RenewalRateLimited}
	if !malformedRetry && len(retries) == 1 {
		for retry := range retries {
			failure.RetryAfter = retry
		}
	}
	return failure
}
