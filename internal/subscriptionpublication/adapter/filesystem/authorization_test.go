package filesystem

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestServingAuthorizationProvesCurrentAndRefusesPriorToken(t *testing.T) {
	priorClient := http.DefaultClient
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/s/current/base64":
			response.WriteHeader(http.StatusOK)
		case "/s/prior/base64":
			http.Error(response, "not found", http.StatusNotFound)
		default:
			response.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = priorClient }()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	if err := proveServingAuthorization(context.Background(), host, servingAuthorization{Token: "current", ListenPort: uint16(port)}, "prior"); err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) { response.WriteHeader(http.StatusOK) })
	if err := proveServingAuthorization(context.Background(), host, servingAuthorization{Token: "current", ListenPort: uint16(port)}, "prior"); err == nil {
		t.Fatal("prior token remained accepted")
	}
}
