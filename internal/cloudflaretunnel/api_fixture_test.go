package cloudflaretunnel

import "net/http"

// NewFixtureHTTPAPI exposes a custom endpoint only to Seam Verification.
func NewFixtureHTTPAPI(client *http.Client, baseURL string, resolver NameServerResolver) API {
	return newHTTPAPI(client, baseURL, resolver)
}
