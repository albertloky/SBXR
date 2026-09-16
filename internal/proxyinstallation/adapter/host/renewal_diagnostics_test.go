package host

import "testing"

func TestRenewalFailureSafe(t *testing.T) {
	if (*RenewalFailure)(nil).Safe() != nil {
		t.Fatal("nil failure became recognized")
	}
	if (&RenewalFailure{Kind: "other", RetryAfter: "2026-09-14T16:16:25Z"}).Safe() != nil {
		t.Fatal("unknown failure became recognized")
	}
	invalid := (&RenewalFailure{Kind: RenewalRateLimited, RetryAfter: "tomorrow"}).Safe()
	if invalid == nil || invalid.Kind != RenewalRateLimited || invalid.RetryAfter != "" {
		t.Fatalf("invalid retry did not preserve only the category: %#v", invalid)
	}
	canonical := (&RenewalFailure{Kind: RenewalRateLimited, RetryAfter: "2026-09-15T00:16:25+08:00"}).Safe()
	if canonical == nil || canonical.RetryAfter != "2026-09-14T16:16:25Z" {
		t.Fatalf("retry was not canonicalized: %#v", canonical)
	}
}

func TestClassifyRenewalFailureRequiresLinkedUnambiguousRetry(t *testing.T) {
	tests := []struct {
		name, stderr, retry string
		recognized          bool
	}{
		{
			name:       "certbot final text",
			stderr:     "2026-09-13 13:22:26,973 unrelated\ntoo many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-09-14 16:16:25 UTC: see [documentation URL]\n",
			recognized: true,
			retry:      "2026-09-14T16:16:25Z",
		},
		{
			name:       "explicit urn without retry",
			stderr:     "acme.messages.Error: urn:ietf:params:acme:error:rateLimited :: request refused\n",
			recognized: true,
		},
		{
			name:       "unrelated retry",
			stderr:     "urn:ietf:params:acme:error:rateLimited\nnext retry after 2026-09-14 16:16:25 UTC\n",
			recognized: true,
		},
		{
			name:       "malformed linked retry",
			stderr:     "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after tomorrow UTC\n",
			recognized: true,
		},
		{
			name:       "conflicting linked retries",
			stderr:     "urn:ietf:params:acme:error:rateLimited retry after 2026-09-14 16:16:25 UTC\nurn:ietf:params:acme:error:rateLimited retry after 2026-09-15 16:16:25 UTC\n",
			recognized: true,
		},
		{
			name:   "unknown failure",
			stderr: "2026-09-13T13:22:26Z: certificate command failed\n",
		},
		{
			name:   "urn suffix",
			stderr: "urn:ietf:params:acme:error:rateLimitedWrong retry after 2026-09-14 16:16:25 UTC\n",
		},
		{
			name:   "quoted urn in unrelated output",
			stderr: "debug payload contains urn:ietf:params:acme:error:rateLimited\n",
		},
		{
			name:   "quoted exact-set text in unrelated output",
			stderr: `debug payload contains "too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s"` + "\n",
		},
		{
			name:       "invalid utc suffix",
			stderr:     "urn:ietf:params:acme:error:rateLimited retry after 2026-09-14 16:16:25 UTCBAD\n",
			recognized: true,
		},
		{
			name:       "valid and malformed linked retries",
			stderr:     "urn:ietf:params:acme:error:rateLimited retry after 2026-09-14 16:16:25 UTC, retry after tomorrow UTC\n",
			recognized: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := classifyRenewalFailure(test.stderr)
			if !test.recognized {
				if failure != nil {
					t.Fatalf("unknown stderr classified: %#v", failure)
				}
				return
			}
			if failure == nil || failure.Kind != RenewalRateLimited || failure.RetryAfter != test.retry {
				t.Fatalf("classification = %#v, want retry %q", failure, test.retry)
			}
		})
	}
}

func TestBoundedRenewalDiagnosticOverflowRefusesClassification(t *testing.T) {
	capture := &boundedRenewalDiagnostic{}
	input := append([]byte("urn:ietf:params:acme:error:rateLimited\n"), make([]byte, maxRenewalDiagnosticBytes)...)
	if written, err := capture.Write(input); err != nil || written != len(input) {
		t.Fatalf("bounded writer = %d, %v", written, err)
	}
	if !capture.overflow || capture.failure() != nil {
		t.Fatalf("overflow was classified: overflow=%v failure=%#v", capture.overflow, capture.failure())
	}
}
