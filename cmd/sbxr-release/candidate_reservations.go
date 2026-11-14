package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"reflect"
)

// A reservation preserves unresolved authority. It is neither unsigned proof
// nor a signed burn, and grants no cleanup, signing or publication action.
type candidateReservation struct {
	Assets                      []observedAsset `json:"assets"`
	Commit                      string          `json:"commit"`
	QualificationManifestSHA256 string          `json:"qualification_manifest_sha256,omitempty"`
	ReleaseID                   int64           `json:"release_id"`
	ReleaseIndexSHA256          string          `json:"release_index_sha256"`
	RunID                       string          `json:"run_id"`
	Sequence                    uint64          `json:"sequence"`
	SigningState                string          `json:"signing_state"`
	Tag                         string          `json:"tag"`
}

// Source-controlled retention decisions; see ADR-0032. Return fresh values so
// callers cannot mutate the policy. Changing this record requires a separate review.
func approvedCandidateReservations() []candidateReservation {
	return []candidateReservation{{
		Tag: "v3.1.129", Sequence: 203, ReleaseID: 426359967,
		Commit: "3656473eb694f18018c1ebbd95829dfe96ed8e3c", RunID: "40644460970", SigningState: "unknown",
		ReleaseIndexSHA256: "44d06c277c7f116fbf76d67841524b9ececca2c6fbeb89521823e9b8858bc668",
		Assets: []observedAsset{
			{ID: 684172605, Name: "install.sh", Size: 76781, Digest: "acd87640b35ab94e5b094348e47748cc417d97a2afeffe373d75e808a1eb518a"},
			{ID: 684172610, Name: "release-index.json", Size: 609, Digest: "44d06c277c7f116fbf76d67841524b9ececca2c6fbeb89521823e9b8858bc668"},
			{ID: 684172607, Name: "sbxr-linux-amd64.tar.gz", Size: 6195309, Digest: "0dcb441160c1873b4833eaed4fae4c27632f2e8f6871f52a37f09c5948a4cdeb"},
			{ID: 684172609, Name: "sbxr-linux-arm64.tar.gz", Size: 5321872, Digest: "b7a1b60e6f16f8f9de0406ca219d15e0901ca817a679cfa54095a09c2dee6d0e"},
		},
	}, {
		Tag: "v3.1.130", Sequence: 204, ReleaseID: 427453228,
		Commit: "8ef6898573d8e7886d11c65b693f79d7c502787f", RunID: "40811037642", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "96d95146293481005b8977aac80c35e088a681d6c135cf2c00e7ee103b92e47c",
		QualificationManifestSHA256: "0fe088fd0cd19a7bd27e0dc62ab7c510736ba7991cc827d45a85d140749334bf",
		Assets: []observedAsset{
			{ID: 687290587, Name: "install.sh", Size: 76781, Digest: "f0e30ec1c69d12e15ab71c649d13f82502a913b5738d9762590f04e9f2523bf1"},
			{ID: 687290585, Name: "release-index.json", Size: 609, Digest: "96d95146293481005b8977aac80c35e088a681d6c135cf2c00e7ee103b92e47c"},
			{ID: 687290581, Name: "sbxr-linux-amd64.tar.gz", Size: 6223869, Digest: "ad40ce76868fa253cad6048a5eec3963d5e5e3b7a771001f2905877ba1f98dc9"},
			{ID: 687290588, Name: "sbxr-linux-arm64.tar.gz", Size: 5273247, Digest: "a44812c96362a949c00353dcb73538fb430d2b1a4b6c7366ee8f719ddffa8b94"},
		},
	}, {
		Tag: "v3.1.131", Sequence: 205, ReleaseID: 427637410,
		Commit: "d4836de007708a77c2bff6e32d5e766eeefaa51e", RunID: "40840504747", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "fc56560d8a687cc2130ce9e6688c9881dbbd80a721280eafc823d18103fb536f",
		QualificationManifestSHA256: "075aa2762751c3ac21d20bb1123db18755077dc85b70bec7f5054c2cf85e49f0",
		Assets: []observedAsset{
			{ID: 687941902, Name: "install.sh", Size: 76781, Digest: "b9867b20e7f737cf144a09078d2ed7ec8c8e8f4a2ecad4bf9bc64ad1d7af11e1"},
			{ID: 687941904, Name: "release-index.json", Size: 609, Digest: "fc56560d8a687cc2130ce9e6688c9881dbbd80a721280eafc823d18103fb536f"},
			{ID: 687941905, Name: "sbxr-linux-amd64.tar.gz", Size: 6223933, Digest: "878c4f450c8962c892a0f4fe5aa62080a25f97988a20d540cc8cc4cb82fe87f7"},
			{ID: 687941901, Name: "sbxr-linux-arm64.tar.gz", Size: 5273213, Digest: "18068729f1793802e22d56466cfd34235f5652ce1ac45c2fa40af0fca4bcb435"},
		},
	}, {
		Tag: "v3.1.132", Sequence: 206, ReleaseID: 429718783,
		Commit: "d842eb0832b512be2c133b4cc4f4887c7f928f0e", RunID: "41165244627", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "fdb387061012c94194924dc8614726e3d00ad0eac01930c05bd3e3a7908cc27f",
		QualificationManifestSHA256: "adc286ca5421cae1c114eb9f1f9718f7934a9deb691555b40331ef527d4d14cb",
		Assets: []observedAsset{
			{ID: 694346722, Name: "install.sh", Size: 76781, Digest: "ce6a52c36115b4962b40f3299dd1aa28f19efc71e812bc580aaf249b759c8332"},
			{ID: 694346718, Name: "release-index.json", Size: 609, Digest: "fdb387061012c94194924dc8614726e3d00ad0eac01930c05bd3e3a7908cc27f"},
			{ID: 694346720, Name: "sbxr-linux-amd64.tar.gz", Size: 6223859, Digest: "89c76958a4a8108225494348b5906b0fe810103d2b5c2dd5bd26a9a852a5886d"},
			{ID: 694346717, Name: "sbxr-linux-arm64.tar.gz", Size: 5274282, Digest: "cdfb47d3582950ea343b20a3e9b2701526f2330f3f313bb9967b8b7a90521845"},
		},
	}, {
		Tag: "v3.1.133", Sequence: 207, ReleaseID: 429811498,
		Commit: "10c6891d8a906031a13786dbe7a3dc8f77bc7dc0", RunID: "41181652726", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "24c525e0667a420018b360397608c0b953213c33b795c8a49e1eecc261aa10d9",
		QualificationManifestSHA256: "43523b10bf5d8b245a10eb9c789798125383deb2d5aa02e8f62079d577afc607",
		Assets: []observedAsset{
			{ID: 694826560, Name: "install.sh", Size: 76781, Digest: "8dc8cb7259c852e282a330b39d4a179d2964053d04f561d57f83a0a2358e473f"},
			{ID: 694826558, Name: "release-index.json", Size: 609, Digest: "24c525e0667a420018b360397608c0b953213c33b795c8a49e1eecc261aa10d9"},
			{ID: 694826556, Name: "sbxr-linux-amd64.tar.gz", Size: 6227987, Digest: "e552bf247893d3f589b1c57f4155096130278bc4ffffa14f3ba25853c66b99dd"},
			{ID: 694826561, Name: "sbxr-linux-arm64.tar.gz", Size: 5278150, Digest: "2011005964a4cad8e1364fe87f753892fa0ef7bb0e1b4b2b70cfa38379ea1a45"},
		},
	}, {
		Tag: "v3.1.134", Sequence: 208, ReleaseID: 429914221,
		Commit: "3da13ff83de223209be9da7a5c64ca49c67c1c8e", RunID: "41196706730", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "5684a8bcd3075fd28bc7fd775571ed04ed76402d4efcfed78e82434707af8317",
		QualificationManifestSHA256: "45c7648310974d928475e4efcc21dcc5bef208fbffbbfbf733b4747374029a98",
		Assets: []observedAsset{
			{ID: 695291740, Name: "install.sh", Size: 76781, Digest: "2475a2669e24acda2d3e749e6ca55ede762876bf5a47759653a6304bc75ac5d1"},
			{ID: 695291739, Name: "release-index.json", Size: 609, Digest: "5684a8bcd3075fd28bc7fd775571ed04ed76402d4efcfed78e82434707af8317"},
			{ID: 695291742, Name: "sbxr-linux-amd64.tar.gz", Size: 6227897, Digest: "39cf7ac2a20b79d426885e2c8e110846548cf4d6e9d5adcbbe3c7e4996aebe5c"},
			{ID: 695291745, Name: "sbxr-linux-arm64.tar.gz", Size: 5278242, Digest: "ee0fd7ce9441894027a8635113b908cee76fe655a55008b412c27664a448b395"},
		},
	}, {
		Tag: "v3.1.135", Sequence: 209, ReleaseID: 430383576,
		Commit: "fef684ddb6b6eb24dbe082beb631fc251ad2e86d", RunID: "41274423664", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "17bb19bcb4c726c3f8312406a7797d62dc80af82cd77e5afbea4f6f58a4f2bb3",
		QualificationManifestSHA256: "b8aeba33c8567a1c5c86b40b0c7f634756a709253fedbb536ddf0083f5087f74",
		Assets: []observedAsset{
			{ID: 697429273, Name: "install.sh", Size: 76781, Digest: "8185a491eadd137bec6346d0fc7447da2d75b084e16f479c1a0f2f84cc563ece"},
			{ID: 697429272, Name: "release-index.json", Size: 609, Digest: "17bb19bcb4c726c3f8312406a7797d62dc80af82cd77e5afbea4f6f58a4f2bb3"},
			{ID: 697429269, Name: "sbxr-linux-amd64.tar.gz", Size: 6234265, Digest: "c740e22bf416b16439cb66f26f1e879c5830cdbaafa90c9930882b3ea69ec7f5"},
			{ID: 697429270, Name: "sbxr-linux-arm64.tar.gz", Size: 5276308, Digest: "daaac9732682f642e8787d99ad80ce3cd921cb89a5b7b93a8d1cdfaec350234c"},
		},
	}, {
		Tag: "v3.1.136", Sequence: 210, ReleaseID: 430449719,
		Commit: "00243e0104783ce0b79149b58c29b8e10b5d0e85", RunID: "41285797719", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "d4a42f0f3f843da35820af7124a00adbc4f04302ba7b1b6f95b99d65ea18ef7d",
		QualificationManifestSHA256: "31a30c120c24c7ea572a826b3842279345404de3ac8a5ed564b410f514a262f8",
		Assets: []observedAsset{
			{ID: 697754584, Name: "install.sh", Size: 76781, Digest: "678cc0eefebba1030a068eca29edde9d5cbcfd07209c80fd870c09dd713e0fc7"},
			{ID: 697754586, Name: "release-index.json", Size: 609, Digest: "d4a42f0f3f843da35820af7124a00adbc4f04302ba7b1b6f95b99d65ea18ef7d"},
			{ID: 697754587, Name: "sbxr-linux-amd64.tar.gz", Size: 6232230, Digest: "6cc1557a7d50050c9e542804e2dce472229980f504ecc5bb359677269289554c"},
			{ID: 697754588, Name: "sbxr-linux-arm64.tar.gz", Size: 5277140, Digest: "c984f658a923b42d4edf7dad124aa713bc207d03ba03a45ec4ceae1509b77c7e"},
		},
	}, {
		Tag: "v3.1.137", Sequence: 211, ReleaseID: 430636507,
		Commit: "a0abe154f4380b2c2f5d28a979c9417d4059e90d", RunID: "41312490744", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "5bf9794eef667e8459eda7e24c6d0e4d9aed687bed7cae8e6297273c46185d68",
		QualificationManifestSHA256: "81107d0cbeed9c0b3f2c759938065d08259966411acb68c1f1d01e282280989e",
		Assets: []observedAsset{
			{ID: 698562875, Name: "install.sh", Size: 76781, Digest: "d5d445d0ef1c91a21fec68b570d2320d6a720eb20aefe976b30eb9ddd91b05fd"},
			{ID: 698562865, Name: "release-index.json", Size: 609, Digest: "5bf9794eef667e8459eda7e24c6d0e4d9aed687bed7cae8e6297273c46185d68"},
			{ID: 698562869, Name: "sbxr-linux-amd64.tar.gz", Size: 6231471, Digest: "da0f81c9d312236788ddb5cd624eb5eca0c0faec80a8d1cc4a133b513d315d85"},
			{ID: 698562874, Name: "sbxr-linux-arm64.tar.gz", Size: 5277144, Digest: "e5d6deb730d54393a1fd3fd1c8d83db543c9975999b5ed6d38f66ebc31b92fad"},
		},
	}, {
		Tag: "v3.1.138", Sequence: 212, ReleaseID: 434759360,
		Commit: "13431bc29500bf20dc108dc325590403d0ca056c", RunID: "41958829811", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "f006de0f4719bc8a6fe21af86a11fd837cc20cf7e73911e13b905e0cdd187a98",
		QualificationManifestSHA256: "30bbbeb56f16bb16ebc6be0cb2dbfa305cc16e403d0c3a609dc0918ac2591b74",
		Assets: []observedAsset{
			{ID: 711955170, Name: "install.sh", Size: 76781, Digest: "ce5eb38b4ed36acaa538cba191be8cf6b07c62a57957ed9703095f76634e9263"},
			{ID: 711955169, Name: "release-index.json", Size: 609, Digest: "f006de0f4719bc8a6fe21af86a11fd837cc20cf7e73911e13b905e0cdd187a98"},
			{ID: 711955171, Name: "sbxr-linux-amd64.tar.gz", Size: 6231778, Digest: "38b156d63f4f0fb9e56ed184298578497b27a6a78a086b97cc3399620a69db76"},
			{ID: 711955172, Name: "sbxr-linux-arm64.tar.gz", Size: 5332376, Digest: "0b47b5925a941ffc7c46d7f45dda305b4551456cf43b6138d32437c5b5543253"},
		},
	}, {
		Tag: "v3.1.139", Sequence: 213, ReleaseID: 435196915,
		Commit: "f067ca24e9bb0d2bc3641ad6c96d44b41dcdb6f3", RunID: "42023983739", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf",
		QualificationManifestSHA256: "e0ce70ea6c28537a3f8e33b1f29a6af75f0037ff87b572eb5e0cd201ffa3bc4c",
		Assets: []observedAsset{
			{ID: 713400894, Name: "install.sh", Size: 76781, Digest: "b1d9a300b98cf4a9b43c091df7a4df389e0ec6e095a64220d39777d130156244"},
			{ID: 713400892, Name: "release-index.json", Size: 609, Digest: "be311736e8d780cc382772461570a2af540d593b21e9956707cee06885a49fcf"},
			{ID: 713400881, Name: "sbxr-linux-amd64.tar.gz", Size: 6236661, Digest: "b6863602a4c4aeaaaa9e4015b0fd784cfba40a4051b007118d59970a302dc8d5"},
			{ID: 713400886, Name: "sbxr-linux-arm64.tar.gz", Size: 5335640, Digest: "667326fc04d4554fcfcf5fb86d314e04bc4e14f6a307a0d9a20c975ef3e4c7aa"},
		},
	}, {
		Tag: "v3.1.140", Sequence: 214, ReleaseID: 437573394,
		Commit: "3c3735dcd3ebca409ccdaba277a0d50deb0b9432", RunID: "42370644704", SigningState: "unknown",
		ReleaseIndexSHA256: "acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69",
		Assets: []observedAsset{
			{ID: 720694599, Name: "install.sh", Size: 76781, Digest: "3a9276acd48156aa72bec598c7cc73c7a2fb59ac5b20cc0f606b390e5a7ccf97"},
			{ID: 720694593, Name: "release-index.json", Size: 609, Digest: "acbe7179311bd52e2b83f9a063747a6a515c0047e754002a4bef59cd80f5fb69"},
			{ID: 720694592, Name: "sbxr-linux-amd64.tar.gz", Size: 6236680, Digest: "2744f7f9d2c5b5fcc79f061a5b0cff2e7d288a302a1847ee17ec50f2010d1923"},
			{ID: 720694600, Name: "sbxr-linux-arm64.tar.gz", Size: 5335593, Digest: "842b39c302535f6a07927e678a25f05ba028a47f13cddf12c51cf84ebe7cc9df"},
		},
	}, {
		Tag: "v3.1.141", Sequence: 215, ReleaseID: 438186606,
		Commit: "84af948bc2a1d92607aa2e6b902512b648133c43", RunID: "42470439088", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b",
		QualificationManifestSHA256: "8a9a38a86f2e12b92689c715021d02b51b7aab402a2735b3329231c1cad6f332",
		Assets: []observedAsset{
			{ID: 723667643, Name: "install.sh", Size: 76781, Digest: "ab42ff6477a5fd205580341837e5a1d07db7fd76c8e57052778ada51f49f9f66"},
			{ID: 723667644, Name: "release-index.json", Size: 609, Digest: "07d718204039c8026b42157097aca1c8bf9c3ee537d6c3a4b25bf098c5e33d0b"},
			{ID: 723667639, Name: "sbxr-linux-amd64.tar.gz", Size: 6236654, Digest: "382567563476de20bf3e48ce8a0038aeb191675fb5e4625585f546e973697ab7"},
			{ID: 723667642, Name: "sbxr-linux-arm64.tar.gz", Size: 5335609, Digest: "1d59594041a9459355a8317a588b9dfa61e8614b886a3a98d4f07c44e8968fd2"},
		},
	}, {
		Tag: "v3.1.142", Sequence: 216, ReleaseID: 443034374,
		Commit: "11aaa5ac6d327d2237fc5fb79bbcff24fc4bc02e", RunID: "43226718845", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "6ff736f4217abecb8237f207453ae571ec1acda25910b6ad87f8e80df4f23ef8",
		QualificationManifestSHA256: "3eefdb8c1f8e9afd0efacda45bfb5c8acbf5c90e58729a333109de9c39c27b5e",
		Assets: []observedAsset{
			{ID: 739727621, Name: "install.sh", Size: 76781, Digest: "5e585878252d639acd5a9d51f38ba2cd5dccb77b0bb54a71a791e1775b3a7103"},
			{ID: 739727622, Name: "release-index.json", Size: 609, Digest: "6ff736f4217abecb8237f207453ae571ec1acda25910b6ad87f8e80df4f23ef8"},
			{ID: 739727626, Name: "sbxr-linux-amd64.tar.gz", Size: 6241059, Digest: "9d13c3986401a5ad646679b31228f25c9ddd914188ce7bb2b39196d4f341bcd7"},
			{ID: 739727618, Name: "sbxr-linux-arm64.tar.gz", Size: 5271842, Digest: "65775973b3c079a77532bbb62e1c289324bf0b7269d41bb79ed467ced4df1b11"},
		},
	}, {
		Tag: "v3.1.143", Sequence: 217, ReleaseID: 445168533,
		Commit: "80a35da8c4ef94d15db00762a52e5548459e320a", RunID: "43575753539", SigningState: "unknown",
		ReleaseIndexSHA256: "34db70d4b0e7c07004b4e7931ce5181a73773fe0f924ee0c8268a06ed488086a",
		Assets: []observedAsset{
			{ID: 746937416, Name: "install.sh", Size: 76781, Digest: "6f3952e00c19afd3b7ff3892929381d547bbccc7900975170d7b6a6d5c6a1207"},
			{ID: 746937413, Name: "release-index.json", Size: 609, Digest: "34db70d4b0e7c07004b4e7931ce5181a73773fe0f924ee0c8268a06ed488086a"},
			{ID: 746937418, Name: "sbxr-linux-amd64.tar.gz", Size: 6238647, Digest: "d63beb8f9060b3c77d99150228e6c4b1afd2d3cd12bdf82b34a60083b1bc7e07"},
			{ID: 746937415, Name: "sbxr-linux-arm64.tar.gz", Size: 5271822, Digest: "f9bed1eb1429e5eaf19b3e36353568d41b554f537711d15415014f74e35c7fa6"},
		},
	}}
}

func reservedCandidate(tag string, sequence uint64, releaseID int64) bool {
	for _, r := range approvedCandidateReservations() {
		if tag == r.Tag || sequence == r.Sequence || releaseID == r.ReleaseID {
			return true
		}
	}
	return false
}

// Only pre-reservation historical facts may omit this field. Every subsequent
// candidate must bind the exact policy; omission cannot restore old allocation.
func validCandidateReservations(facts qualificationFacts) bool {
	if facts.ReservedIdentities == nil {
		for _, r := range approvedCandidateReservations() {
			if facts.Candidate.ASequence >= r.Sequence || facts.Candidate.BSequence >= r.Sequence {
				return false
			}
		}
		return true
	}
	if !reflect.DeepEqual(facts.ReservedIdentities, approvedCandidateReservations()) {
		return false
	}
	for _, r := range facts.ReservedIdentities {
		if tagPresent(facts.Tags, r.Tag) {
			return false
		}
		for _, release := range facts.Releases {
			if release.Tag == r.Tag || release.ID == r.ReleaseID || release.Sequence != nil && *release.Sequence == r.Sequence {
				return false
			}
		}
		if collidesWithBurned(facts.BurnedIdentities, r.Tag, r.Sequence) {
			return false
		}
	}
	return true
}

type reservationRelease struct {
	Assets     []observedAsset `json:"assets"`
	Body       string          `json:"body"`
	Commit     string          `json:"commit"`
	Draft      bool            `json:"draft"`
	ID         int64           `json:"id"`
	Immutable  bool            `json:"immutable"`
	Prerelease bool            `json:"prerelease"`
	Tag        string          `json:"tag"`
}
type reservationRef struct {
	State string          `json:"state"`
	Value json.RawMessage `json:"value"`
}
type reservationIdentityRefs struct {
	Burn    reservationRef `json:"burn"`
	Release reservationRef `json:"release"`
	Tag     string         `json:"tag"`
}
type reservationObservations struct {
	Refs     []reservationIdentityRefs `json:"refs"`
	Releases []reservationRelease      `json:"releases"`
}

func checkCandidateReservations(observed reservationObservations, allowed []string) bool {
	policy := approvedCandidateReservations()
	// The Owner-approved exception is exactly these fifteen retained identities.
	if len(policy) != 15 || observed.Releases == nil || len(observed.Refs) != len(policy) {
		return false
	}
	for i, r := range policy {
		refs := observed.Refs[i]
		if refs.Tag != r.Tag || refs.Release.State != "absent" || !bytes.Equal(refs.Release.Value, []byte("null")) || refs.Burn.State != "absent" || !bytes.Equal(refs.Burn.Value, []byte("null")) {
			return false
		}
	}
	allow := map[string]bool{}
	for _, tag := range allowed {
		if !validTag(tag) || reservedCandidate(tag, 0, 0) || allow[tag] {
			return false
		}
		allow[tag] = true
	}
	seenIDs := map[int64]bool{}
	seenTags := map[string]bool{}
	found := map[string]bool{}
	for _, release := range observed.Releases {
		if release.ID <= 0 || release.Tag == "" || seenIDs[release.ID] || seenTags[release.Tag] {
			return false
		}
		seenIDs[release.ID] = true
		seenTags[release.Tag] = true
		reserved := false
		for _, r := range policy {
			if release.ID != r.ReleaseID && release.Tag != r.Tag {
				continue
			}
			expected := reservationRelease{Assets: r.Assets, Body: "Qualification pending.", Commit: r.Commit, Draft: true, ID: r.ReleaseID, Tag: r.Tag}
			if found[r.Tag] || !reflect.DeepEqual(release, expected) {
				return false
			}
			found[r.Tag] = true
			reserved = true
			break
		}
		if !reserved && release.Draft && !allow[release.Tag] {
			return false
		}
	}
	return len(found) == len(policy)
}

func runCandidateReservations(args []string, input io.Reader, output io.Writer) error {
	refused := errors.New("candidate reservation refused")
	flags := flag.NewFlagSet("candidate-reservations", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policy := flags.Bool("policy", false, "read the fixed reservation policy")
	allowedJSON := flags.String("allowed-draft-tags", "[]", "current authenticated workflow candidate tags")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return refused
	}
	if *policy {
		if *allowedJSON != "[]" {
			return refused
		}
	} else {
		var allowed []string
		if !decodeCanonical([]byte(*allowedJSON), &allowed) || allowed == nil {
			return refused
		}
		raw, err := io.ReadAll(io.LimitReader(input, 16<<20+1))
		var observed reservationObservations
		if err != nil || len(raw) > 16<<20 || !decodeCanonical(raw, &observed) || !checkCandidateReservations(observed, allowed) {
			return refused
		}
	}
	body, err := marshalCanonical(approvedCandidateReservations())
	if err != nil {
		return refused
	}
	_, err = output.Write(body)
	return err
}
