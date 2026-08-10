package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/albertloky/SBXR/internal/connectionprofiles"
)

func TestClientAccessHandoffAcceptsOnlyExactTypedRequests(t *testing.T) {
	valid := clientAccessHandoffRequest{Schema: 1, Mode: "change", Action: clientAccessRotateProfile, Profile: string(connectionprofiles.AnyTLSProfileID), ChangeSet: "client-access-0001"}
	if !validClientAccessHandoff(valid) || !validClientAccessHandoff(clientAccessHandoffRequest{Schema: 1, Mode: "view"}) || !validClientAccessHandoff(clientAccessHandoffRequest{Schema: 1, Mode: "recover", ChangeSet: valid.ChangeSet}) {
		t.Fatal("exact Client Access requests were refused")
	}
	for _, changed := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "change", Action: clientAccessRotateProfile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "change", Action: clientAccessRotateAllProfiles, Profile: valid.Profile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "change", Action: "run-command", Profile: valid.Profile, ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "view", ChangeSet: valid.ChangeSet},
		{Schema: 1, Mode: "recover", Action: clientAccessRotateProfile, ChangeSet: valid.ChangeSet},
	} {
		if validClientAccessHandoff(changed) {
			t.Fatalf("unsafe request accepted: %+v", changed)
		}
	}
	var encoded bytes.Buffer
	if err := writeClientAccessMessage(&encoded, valid); err != nil {
		t.Fatal(err)
	}
	var decoded clientAccessHandoffRequest
	if err := readClientAccessMessage(&encoded, &decoded); err != nil || decoded != valid {
		t.Fatalf("strict round trip failed: %+v %v", decoded, err)
	}
	unknown := []byte(`{"schema":1,"mode":"view","command":"id"}`)
	framed := make([]byte, 4)
	binary.BigEndian.PutUint32(framed, uint32(len(unknown)))
	if err := readClientAccessMessage(bytes.NewReader(append(framed, unknown...)), &decoded); err == nil {
		t.Fatal("unknown privileged field was accepted")
	}
	if strings.Contains(valid.String(), "client-access") {
		t.Fatal("request rendering exposed privileged facts")
	}
}

func TestManagedProviderHandoffAcceptsOnlyExactReviewedActions(t *testing.T) {
	requests := []clientAccessHandoffRequest{
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareReplace, ChangeSet: "provider-0001", Token: "cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRemove, ChangeSet: "provider-0002"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRotate, ChangeSet: "provider-0003"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateIP, ChangeSet: "provider-0004", OwnerEmail: "owner@example.com", Agreement: true},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateDomain, ChangeSet: "provider-0005", OwnerEmail: "owner@example.com", Agreement: true},
	}
	for _, request := range requests {
		if !validClientAccessHandoff(request) {
			t.Fatalf("exact managed provider request was refused: %+v", request)
		}
		request.Action = clientAccessRotateAllProfiles
		if validClientAccessHandoff(request) {
			t.Fatalf("mixed Client Access/provider authority was accepted: %+v", request)
		}
	}
	for _, request := range []clientAccessHandoffRequest{
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareReplace, ChangeSet: "provider-0001", Token: "short"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCloudflareRemove, ChangeSet: "provider-0002", Token: "cfat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{Schema: 1, Mode: "provider", ProviderAction: managedCertificateIP, ChangeSet: "provider-0004", OwnerEmail: "owner@example.com"},
		{Schema: 1, Mode: "provider", ProviderAction: "shell", ChangeSet: "provider-0006"},
	} {
		if validClientAccessHandoff(request) {
			t.Fatalf("unsafe managed provider request was accepted: %+v", request)
		}
	}
}
