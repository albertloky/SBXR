package softwarelifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestBuildReleaseIndexBindsInstallAndTheExactFourQualifiedArchives(t *testing.T) {
	assets := []ReleaseIndexAsset{
		{Role: ApplicationAMD64, Name: "sbxr-linux-amd64.tar.gz", Bytes: []byte("amd64 application")},
		{Role: ApplicationARM64, Name: "sbxr-linux-arm64.tar.gz", Bytes: []byte("arm64 application")},
		{Role: ComponentsAMD64, Name: "sbxr-components-linux-amd64.tar.gz", Bytes: []byte("amd64 components")},
		{Role: ComponentsARM64, Name: "sbxr-components-linux-arm64.tar.gz", Bytes: []byte("arm64 components")},
		{Role: Bootstrap, Name: "install.sh", Bytes: []byte("#!/bin/sh\nexit 1\n")},
	}
	body, err := BuildReleaseIndex(ReleaseIndexRequest{Version: "1.0.0", Sequence: 1, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", StateSchema: 2, MinimumUpdaterSchema: 1, Assets: assets})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"product":"sbxr","repository":"albertloky/SBXR","version":"1.0.0","sequence":1,"tag":"v1.0.0","commit":"0123456789abcdef0123456789abcdef01234567","state_schema":2,"minimum_updater_schema":1,"assets":[`
	for index, asset := range assets {
		digest := sha256.Sum256(asset.Bytes)
		if index != 0 {
			want += ","
		}
		want += fmt.Sprintf(`{"role":%q,"name":%q,"size":%d,"sha256":%q}`, asset.Role, asset.Name, len(asset.Bytes), hex.EncodeToString(digest[:]))
	}
	want += `]}`
	if string(body) != want {
		t.Fatalf("release index = %s\nwant = %s", body, want)
	}

	for _, changed := range []ReleaseIndexRequest{
		{Version: "1.0.0", Sequence: 1, Tag: "v1.0.1", Commit: "0123456789abcdef0123456789abcdef01234567", StateSchema: 2, MinimumUpdaterSchema: 1, Assets: assets},
		{Version: "1.0.0", Sequence: 1, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", StateSchema: 2, MinimumUpdaterSchema: 1, Assets: assets[:3]},
		{Version: "1.0.0", Sequence: 1, Tag: "v1.0.0", Commit: "0123456789abcdef0123456789abcdef01234567", StateSchema: 2, MinimumUpdaterSchema: 1, Assets: append(append([]ReleaseIndexAsset(nil), assets[:3]...), assets[2])},
	} {
		if _, err := BuildReleaseIndex(changed); err == nil {
			t.Fatalf("invalid release index accepted: %+v", changed)
		}
	}
}
