package cloudflaretunnel

import "net/http"

// NewFixtureHTTPAPI exposes a custom endpoint only to Seam Verification.
func NewFixtureHTTPAPI(client *http.Client, baseURL string, resolver NameServerResolver) API {
	return newHTTPAPI(client, baseURL, resolver)
}

// NewFixtureMutationAPI exposes the provider and loopback seams only to Seam Verification.
func NewFixtureMutationAPI(client *http.Client, baseURL string, resolver NameServerResolver, origins OriginObserver) *httpAPI {
	api := newHTTPAPI(client, baseURL, resolver)
	api.origins = origins
	return api
}
