package cloudflaretunnel_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/cloudflaretunnel"
)

type staticResolver struct {
	names []*net.NS
	err   error
}

func (resolver staticResolver) LookupNS(context.Context, string) ([]*net.NS, error) {
	return resolver.names, resolver.err
}

func TestHTTPAPIParsesOfficialShapesWithScopedAuthenticationAndPagination(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.URL.RequestURI())
		if got := request.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if strings.Contains(request.URL.String(), "MANAGEMENT-TOKEN-MARKER") || request.ContentLength > 0 {
			t.Errorf("secret left Authorization header: %s length %d", request.URL, request.ContentLength)
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/user/tokens/verify":
			fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"`+tokenID+`","status":"active","unexpected":"PROVIDER-FIELD-MARKER"}}`)
		case "/zones":
			if request.URL.Query().Get("status") != "active" || request.URL.Query().Get("per_page") != "50" || request.URL.Query().Has("account.id") || request.URL.Query().Has("name") {
				t.Errorf("zone scope query = %s", request.URL.RawQuery)
			}
			if request.URL.Query().Get("page") == "1" {
				fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":50,"total_pages":2,"count":0,"total_count":1}}`)
				return
			}
			fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[{"id":"`+zoneID+`","name":"example.com","status":"active","name_servers":["ada.ns.cloudflare.com","bob.ns.cloudflare.com"],"account":{"id":"`+accountID+`","name":"Selected account"}}],"result_info":{"page":2,"per_page":50,"total_pages":2,"count":1,"total_count":1}}`)
		case "/zones/" + zoneID + "/dns_records":
			fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":1,"total_pages":0,"count":0,"total_count":0}}`)
		case "/accounts/" + accountID + "/cfd_tunnel":
			fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":[],"result_info":{"page":1,"per_page":1,"total_pages":0,"count":0,"total_count":0}}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{names: []*net.NS{{Host: "bob.ns.cloudflare.com."}, {Host: "ada.ns.cloudflare.com."}}})
	observed, err := api.Observe(context.Background(), cloudflaretunnel.ObservationRequest{AccountID: accountID, ZoneID: zoneID, ZoneName: "example.com", Token: managementToken})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Account.ID != accountID || observed.Account.Name != "Selected account" || observed.Zone.ID != zoneID || observed.Token.ID != tokenID || observed.Token.Status != "active" || observed.Token.ExpiresOn != nil || len(observed.Zone.ObservedNameServers) != 2 || !observed.DNSListProven || !observed.TunnelListProven {
		t.Fatalf("Observe() = %+v", observed)
	}
	wantRequests := []string{
		"/user/tokens/verify",
		"/zones?page=1&per_page=50&status=active",
		"/zones?page=2&per_page=50&status=active",
		"/zones/" + zoneID + "/dns_records?page=1&per_page=1",
		"/accounts/" + accountID + "/cfd_tunnel?is_deleted=false&page=1&per_page=1",
	}
	for index, want := range wantRequests {
		got, parseErr := url.QueryUnescape(requests[index])
		if parseErr != nil || got != want {
			t.Fatalf("request %d = %q, want %q", index, got, want)
		}
	}
}

func TestHTTPAPIRefusesMalformedAmbiguousAndUnsafeResponses(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	request := cloudflaretunnel.ObservationRequest{AccountID: accountID, ZoneID: zoneID, ZoneName: "example.com", Token: managementToken}

	for _, test := range []struct {
		name   string
		status int
		body   string
		kind   cloudflaretunnel.APIErrorKind
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"success":false,"errors":[{"message":"PROVIDER-ERROR-MARKER"}]}`, kind: cloudflaretunnel.APIUnauthorized},
		{name: "rate limit", status: http.StatusTooManyRequests, body: `{"success":false,"errors":[{"message":"PROVIDER-ERROR-MARKER"}]}`, kind: cloudflaretunnel.APITemporary},
		{name: "server failure", status: http.StatusServiceUnavailable, body: `PROVIDER-ERROR-MARKER`, kind: cloudflaretunnel.APITemporary},
		{name: "forbidden", status: http.StatusForbidden, body: `{"success":false,"errors":[{"message":"PROVIDER-ERROR-MARKER"}]}`, kind: cloudflaretunnel.APIForbidden},
		{name: "malformed JSON", status: http.StatusOK, body: `{"success":`, kind: cloudflaretunnel.APIMalformed},
		{name: "false success", status: http.StatusOK, body: `{"success":false,"errors":[{"message":"PROVIDER-ERROR-MARKER"}]}`, kind: cloudflaretunnel.APIPermanent},
		{name: "missing result", status: http.StatusOK, body: `{"success":true,"errors":[],"messages":[]}`, kind: cloudflaretunnel.APIMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(test.status)
				fmt.Fprint(response, test.body)
			}))
			defer server.Close()
			api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
			_, gotErr := api.Observe(context.Background(), request)
			assertAPIError(t, gotErr, test.kind)
			var apiError cloudflaretunnel.APIError
			if (test.kind == cloudflaretunnel.APIUnauthorized || test.kind == cloudflaretunnel.APIForbidden) && (!errors.As(gotErr, &apiError) || apiError.RequiredPermission != cloudflaretunnel.UserAPITokensEditPermission) {
				t.Fatalf("authorization refusal required permission = %+v", gotErr)
			}
			if strings.Contains(gotErr.Error(), "PROVIDER-ERROR-MARKER") || strings.Contains(gotErr.Error(), token) {
				t.Fatalf("error leaked provider material: %v", gotErr)
			}
		})
	}

	t.Run("two matching zones are ambiguous", func(t *testing.T) {
		server := officialShapeServer(t, `[{"id":"`+zoneID+`","name":"example.com","status":"active","name_servers":["ada.ns.cloudflare.com"],"account":{"id":"`+accountID+`","name":"Selected account"}},{"id":"`+zoneID+`","name":"example.com","status":"active","name_servers":["ada.ns.cloudflare.com"],"account":{"id":"`+accountID+`","name":"Selected account"}}]`, 2)
		defer server.Close()
		api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
		_, gotErr := api.Observe(context.Background(), request)
		assertAPIError(t, gotErr, cloudflaretunnel.APIAmbiguous)
	})

	t.Run("oversized response is refused", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(response, `{"success":true,"result":{"padding":"`+strings.Repeat("x", (1<<20)+1)+`"}}`)
		}))
		defer server.Close()
		api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
		_, gotErr := api.Observe(context.Background(), request)
		assertAPIError(t, gotErr, cloudflaretunnel.APIMalformed)
	})

	t.Run("unbounded pagination is refused", func(t *testing.T) {
		server := officialShapeServerWithResultInfo(t, `[]`, 0, `{"page":1,"per_page":50,"total_pages":101,"count":0,"total_count":0}`, "active")
		defer server.Close()
		api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
		_, gotErr := api.Observe(context.Background(), request)
		assertAPIError(t, gotErr, cloudflaretunnel.APILimit)
	})

	t.Run("DNS lookup failure is temporary", func(t *testing.T) {
		server := officialShapeServer(t, `[{"id":"`+zoneID+`","name":"example.com","status":"active","name_servers":["ada.ns.cloudflare.com"],"account":{"id":"`+accountID+`","name":"Selected account"}}]`)
		defer server.Close()
		api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{err: fmt.Errorf("DNS PROVIDER-ERROR-MARKER")})
		_, gotErr := api.Observe(context.Background(), request)
		assertAPIError(t, gotErr, cloudflaretunnel.APITemporary)
	})
}

func TestHTTPAPIAttributesSelectedZoneRefusalToDNSWrite(t *testing.T) {
	managementToken, err := cloudflaretunnel.NewManagementToken(token)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/user/tokens/verify":
			fmt.Fprint(response, `{"success":true,"result":{"id":"`+tokenID+`","status":"active"}}`)
		case "/zones":
			response.WriteHeader(http.StatusForbidden)
			fmt.Fprint(response, `{"success":false}`)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	api := cloudflaretunnel.NewFixtureHTTPAPI(server.Client(), server.URL, staticResolver{})
	_, gotErr := api.Observe(context.Background(), cloudflaretunnel.ObservationRequest{AccountID: accountID, ZoneID: zoneID, ZoneName: "example.com", Token: managementToken})
	var apiError cloudflaretunnel.APIError
	if !errors.As(gotErr, &apiError) || apiError.Kind != cloudflaretunnel.APIForbidden || apiError.RequiredPermission != cloudflaretunnel.ZoneReadPermission {
		t.Fatalf("selected-zone authorization refusal = %+v", gotErr)
	}
}

func officialShapeServer(t *testing.T, zones string, counts ...int) *httptest.Server {
	t.Helper()
	count := 1
	if len(counts) > 0 {
		count = counts[0]
	}
	return officialShapeServerWithResultInfo(t, zones, count, fmt.Sprintf(`{"page":1,"per_page":50,"total_pages":1,"count":%d,"total_count":%d}`, count, count), "active")
}

func officialShapeServerWithResultInfo(t *testing.T, zones string, count int, resultInfo, detailStatus string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/user/tokens/verify":
			fmt.Fprint(response, `{"success":true,"errors":[],"messages":[],"result":{"id":"`+tokenID+`","status":"active"}}`)
		case "/zones":
			fmt.Fprintf(response, `{"success":true,"errors":[],"messages":[],"result":%s,"result_info":%s}`, zones, resultInfo)
		case "/zones/" + zoneID + "/dns_records", "/accounts/" + accountID + "/cfd_tunnel":
			fmt.Fprint(response, `{"success":true,"result":[],"result_info":{"page":1,"per_page":1,"total_pages":0,"count":0,"total_count":0}}`)
		default:
			http.NotFound(response, request)
		}
	}))
}

func assertAPIError(t *testing.T, err error, kind cloudflaretunnel.APIErrorKind) {
	t.Helper()
	apiError, ok := err.(cloudflaretunnel.APIError)
	if !ok || apiError.Kind != kind {
		t.Fatalf("error = %#v, want APIError %q", err, kind)
	}
}
