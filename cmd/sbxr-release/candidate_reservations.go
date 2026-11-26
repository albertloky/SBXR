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
	}, {
		Tag: "v3.1.144", Sequence: 218, ReleaseID: 445390275,
		Commit: "a04bcd46ce4a3759a9c67f7b43049437a3f8d914", RunID: "43605935683", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "d24d75239e91d0cdb173fdff10fe8ba704c199b6ba6857e8b64bd952021c1d0e",
		QualificationManifestSHA256: "5ae9b2ef3ac4d6621bc88e76ff0e571a31c063761e9e1681c7fdf7f055941a21",
		Assets: []observedAsset{
			{ID: 747892008, Name: "install.sh", Size: 76781, Digest: "f7863549ba929d72d5d5ecc2cc231dacb917f392ff720e4c437674396ad61d8f"},
			{ID: 747892004, Name: "release-index.json", Size: 609, Digest: "d24d75239e91d0cdb173fdff10fe8ba704c199b6ba6857e8b64bd952021c1d0e"},
			{ID: 747892005, Name: "sbxr-linux-amd64.tar.gz", Size: 6238584, Digest: "46536e76e183058d1ed4493054be990df24f5f041fb95e9c2b25580d5b930666"},
			{ID: 747892012, Name: "sbxr-linux-arm64.tar.gz", Size: 5271862, Digest: "6028cbb24789d2c24c01cfb5431f28ea9a741f96d269018a628614d861dfed6c"},
		},
	}, {
		Tag: "v3.1.145", Sequence: 219, ReleaseID: 445854747,
		Commit: "2443140fcb9fee0180e520350ad9e2cf46263629", RunID: "43681700607", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "1345061e29b4ffaa3b2da16cf150710271bff2e9a59e0fa48bceb5a429c92f0d",
		QualificationManifestSHA256: "a5fa50f2b04c5b85a4dd743500b188ad83c8424d70b3786b0eb1ac3455445d07",
		Assets: []observedAsset{
			{ID: 750053230, Name: "install.sh", Size: 76781, Digest: "5333f5b426283cf56fafab48b709b9664ad8f68baa22a1cc9c26c8c165ace75f"},
			{ID: 750053233, Name: "release-index.json", Size: 609, Digest: "1345061e29b4ffaa3b2da16cf150710271bff2e9a59e0fa48bceb5a429c92f0d"},
			{ID: 750053229, Name: "sbxr-linux-amd64.tar.gz", Size: 6238642, Digest: "9efaf8b8645c79cef576840f18b5b8a961a2116f75e6c5190f734491de3d8269"},
			{ID: 750053231, Name: "sbxr-linux-arm64.tar.gz", Size: 5271806, Digest: "0a1b95bfaf19ff9efb28e2846a23255c877610d569fb517fe0c02cf8708d4947"},
		},
	}, {
		Tag: "v3.1.146", Sequence: 220, ReleaseID: 447230997,
		Commit: "066cbd5aa0814c32d9d6e450fcce30b620249dd9", RunID: "43888940342", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "50adcb3f65a64176a54fa4fe5262543396b1ccba30e8525ab1449c28a73adb40",
		QualificationManifestSHA256: "6ecd1c526d9b6cd714ef4e5a840ec73a0a5268e40f0dac03375194c5605f96c1",
		Assets: []observedAsset{
			{ID: 755378906, Name: "install.sh", Size: 76781, Digest: "7f6bd88269ce91cacde9fbeb98e2e6d37b878778eb6837929826623a46fd54b9"},
			{ID: 755378907, Name: "release-index.json", Size: 609, Digest: "50adcb3f65a64176a54fa4fe5262543396b1ccba30e8525ab1449c28a73adb40"},
			{ID: 755378911, Name: "sbxr-linux-amd64.tar.gz", Size: 6239583, Digest: "76056c60c9f3ced0079c93e37b6bcb905f2f6879e9053a65aa0f2335a709979c"},
			{ID: 755378908, Name: "sbxr-linux-arm64.tar.gz", Size: 5274350, Digest: "89b6f938f7a58d4328a64c91b691b6413470270cef9fdf18e5d04184564339e8"},
		},
	}, {
		Tag: "v3.1.147", Sequence: 221, ReleaseID: 448920065,
		Commit: "9506d078135184594294f2b53bfffed1d0ba2d35", RunID: "44119602131", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "13359c01d4886004368f4056806f027235b8e62af6a79976a802d40e2f73c3e3",
		QualificationManifestSHA256: "68505f68e935c6ef3d3ddd9a54d76e99e56138880276d621c8d720c3a0346f36",
		Assets: []observedAsset{
			{ID: 759837069, Name: "install.sh", Size: 76781, Digest: "59a9d732806e31833ecc701e4cd54de1cee28be101780491ead89123064bd38c"},
			{ID: 759837071, Name: "release-index.json", Size: 609, Digest: "13359c01d4886004368f4056806f027235b8e62af6a79976a802d40e2f73c3e3"},
			{ID: 759837074, Name: "sbxr-linux-amd64.tar.gz", Size: 6244513, Digest: "ae2bedc6abc08316145ea5d8956c8897098c71108f06cf8a2da682b08ba26c54"},
			{ID: 759837068, Name: "sbxr-linux-arm64.tar.gz", Size: 5273215, Digest: "e1b9d150e139b4d8876aab3ac0782d06f9a7e4473b86a69eddac257d05496283"},
		},
	}, {
		Tag: "v3.1.148", Sequence: 222, ReleaseID: 450141673,
		Commit: "2b1ae4d6c702e6eff433cd418b5d616428e71852", RunID: "44321290506", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "c0898423020a77fd05a691304e9282c8a42b0cf52b63f79fdf9f4fa77e04434b",
		QualificationManifestSHA256: "774894328bd2a6347ce873c9a1a2e3d750e08941bcc0a60bd6422edb029d9551",
		Assets: []observedAsset{
			{ID: 763814976, Name: "install.sh", Size: 77206, Digest: "2c6adbcbd46e5f1bc7800b9a9da9cb4ae660ad18b38942b35f61263527575761"},
			{ID: 763814974, Name: "release-index.json", Size: 609, Digest: "c0898423020a77fd05a691304e9282c8a42b0cf52b63f79fdf9f4fa77e04434b"},
			{ID: 763814968, Name: "sbxr-linux-amd64.tar.gz", Size: 6245711, Digest: "5a0a7279695e4a2339c8c23750ddd8dacd564a6c80bb84b32c3a3faea292083e"},
			{ID: 763814975, Name: "sbxr-linux-arm64.tar.gz", Size: 5338627, Digest: "2d3997e8c2244c04e349ba5339bcf6ff4921e4280e5229a255342b9a875522dc"},
		},
	}, {
		Tag: "v3.1.149", Sequence: 223, ReleaseID: 450895501,
		Commit: "e96888ed8e11a47b16ee89aefb1f8491d17a59c6", RunID: "44456189920", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "e2f0ac89f33ba7c234f0a488513dd9f0fb7d8ac56e6e8c50bcfd30f5b874f12b",
		QualificationManifestSHA256: "db2921412d322a7c029d92651f1c5246bc634491d4365df8b694fe93c5e9705c",
		Assets: []observedAsset{
			{ID: 766277215, Name: "install.sh", Size: 77206, Digest: "bef0b5f8342e2cdf452f2e791e4ddec0736f90854401449ad8373ad35bd8bc18"},
			{ID: 766277214, Name: "release-index.json", Size: 609, Digest: "e2f0ac89f33ba7c234f0a488513dd9f0fb7d8ac56e6e8c50bcfd30f5b874f12b"},
			{ID: 766277212, Name: "sbxr-linux-amd64.tar.gz", Size: 6245711, Digest: "2f64a44f227f3bd42a525fb942f966c11498dbd6452dd3f7200abb281f56ef82"},
			{ID: 766277211, Name: "sbxr-linux-arm64.tar.gz", Size: 5338594, Digest: "7be0bb23e932f0905b9c80bf457a94e4139713a959d65683b5ebf8a08219f639"},
		},
	}, {
		Tag: "v3.1.150", Sequence: 224, ReleaseID: 451038149,
		Commit: "2718e77049ddc15b2013c5425591dca9ef083322", RunID: "44478371554", SigningState: "unknown",
		ReleaseIndexSHA256: "f3ba111127897f96844e52dedad7b7e5b85445d8999154dfe5a3e7d758273e98",
		Assets: []observedAsset{
			{ID: 766801935, Name: "install.sh", Size: 77206, Digest: "f77581a2dbc40a6d701d0ef9624070d2662ce02b1f9640b2da285f3836cccde7"},
			{ID: 766801934, Name: "release-index.json", Size: 609, Digest: "f3ba111127897f96844e52dedad7b7e5b85445d8999154dfe5a3e7d758273e98"},
			{ID: 766801933, Name: "sbxr-linux-amd64.tar.gz", Size: 6245862, Digest: "9344aab30a66c052468d681fe5a7e8b2e31467834e33c0a4bf88cfc648152412"},
			{ID: 766801936, Name: "sbxr-linux-arm64.tar.gz", Size: 5338718, Digest: "0eaead6db2c8a484f5f90d1b852a9993b88ec7cfe96f2ec851c48023e7e836bb"},
		},
	}, {
		Tag: "v3.1.151", Sequence: 225, ReleaseID: 451382653,
		Commit: "197497a92b8957cc2f29529edb3ba3a1a3952147", RunID: "44526156427", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "b4d54791aa71a2d5487e5798f0c8417fa421b0821b53130c3959a2e5ecf160d9",
		QualificationManifestSHA256: "e86b024c5356cdead620a9389296cf8aa5816b3c643884ba895572ac0c052bc6",
		Assets: []observedAsset{
			{ID: 767797843, Name: "install.sh", Size: 77206, Digest: "072addcb901df6691abb689170fa93b2d737373a1afbf49d226f423dbfead991"},
			{ID: 767797842, Name: "release-index.json", Size: 609, Digest: "b4d54791aa71a2d5487e5798f0c8417fa421b0821b53130c3959a2e5ecf160d9"},
			{ID: 767797841, Name: "sbxr-linux-amd64.tar.gz", Size: 6254155, Digest: "01b555d67e08bbfb266e02b1edd7031e81d02a5133287a180cedd391cb81ef1e"},
			{ID: 767797844, Name: "sbxr-linux-arm64.tar.gz", Size: 5311244, Digest: "f40a3646a607638a08d8a07c9e93c0ef74782aaf98aa764d5b89989545b968ee"},
		},
	}, {
		Tag: "v3.1.152", Sequence: 226, ReleaseID: 452235987,
		Commit: "73b0c6d6d47d8b9d11c1e6d571bba60f11373a87", RunID: "44663342311", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "b93b39ab6edef7a0e9cc24e6ef28f3e834dd875bad8eafee09689d1d965419ca",
		QualificationManifestSHA256: "9763600934e3444f34bc089992b09a22052e7500b617ae213530439c0e3f2ea4",
		Assets: []observedAsset{
			{ID: 770307842, Name: "install.sh", Size: 77206, Digest: "4d65c8e9726bbc5f3b178849102709fcd785fdad0df64a30fa1563d84dcababb"},
			{ID: 770307846, Name: "release-index.json", Size: 609, Digest: "b93b39ab6edef7a0e9cc24e6ef28f3e834dd875bad8eafee09689d1d965419ca"},
			{ID: 770307839, Name: "sbxr-linux-amd64.tar.gz", Size: 6254225, Digest: "f39cd56dd8715d47848c560b54d37712e0f09de1637c0f6eff92c7276d8c4d5e"},
			{ID: 770307841, Name: "sbxr-linux-arm64.tar.gz", Size: 5311203, Digest: "5907abe52d0228ff667e74096b4eefbd979562b61cc9c84e3a17b6dddcee96a3"},
		},
	}, {
		Tag: "v3.1.153", Sequence: 227, ReleaseID: 452614336,
		Commit: "6f0f507be44b2b2da1fee9d49947b1bfec974d66", RunID: "44721369198", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "08d832c67bee2c4b5762490a5a17d6f15ded9b303ab02b1c617d9c94d091fbdb",
		QualificationManifestSHA256: "ee2c4887d618324ed73383198caca6261ce72cbf8e15279734868e7e813a39de",
		Assets: []observedAsset{
			{ID: 771584033, Name: "install.sh", Size: 77206, Digest: "fe8e40607bbe326fc10caacfb394208ec43a39c8884fee7800ff54455bae56b4"},
			{ID: 771584036, Name: "release-index.json", Size: 609, Digest: "08d832c67bee2c4b5762490a5a17d6f15ded9b303ab02b1c617d9c94d091fbdb"},
			{ID: 771584042, Name: "sbxr-linux-amd64.tar.gz", Size: 6254244, Digest: "b86f1cac4ffc1b682cc5be25009f4988e2e549e24be03b4fa563404d957020b8"},
			{ID: 771584041, Name: "sbxr-linux-arm64.tar.gz", Size: 5311392, Digest: "0d2e301694bf97d9ec66518df4ade389fe94cbc5a4929c4fe28c280990650027"},
		},
	}, {
		Tag: "v3.1.154", Sequence: 228, ReleaseID: 453091507,
		Commit: "ae4005f39e7e509cbe7bab489cb8367be4448634", RunID: "44793775813", SigningState: "unknown",
		ReleaseIndexSHA256: "e3444151ab3294e8f47e90ffc99d82a835bf6c94d30442805c79364853b47600",
		Assets: []observedAsset{
			{ID: 773046202, Name: "install.sh", Size: 77206, Digest: "aa820398a3903ecc6f6f3389eada66f7e1fc7b149a62a58220c8eb57c5362892"},
			{ID: 773046204, Name: "release-index.json", Size: 609, Digest: "e3444151ab3294e8f47e90ffc99d82a835bf6c94d30442805c79364853b47600"},
			{ID: 773046203, Name: "sbxr-linux-amd64.tar.gz", Size: 6254039, Digest: "b38f9e7a4febddbaad3627ca0a76968051731d5beea61cf79b117f62383d8256"},
			{ID: 773046200, Name: "sbxr-linux-arm64.tar.gz", Size: 5311348, Digest: "64233488d5a20bf4f697be7a8b37e324d6bf8e179a8124c5f73870be00957059"},
		},
	}, {
		Tag: "v3.1.155", Sequence: 229, ReleaseID: 453483664,
		Commit: "7fdf2dc6c5c0319b3ebc072ea0d83196e262e635", RunID: "44870708966", SigningState: "unknown",
		ReleaseIndexSHA256: "7c252746ef5e51484e6f8446321867ca404a872b22ecc6b40b20c727809b9c84",
		Assets: []observedAsset{
			{ID: 774625228, Name: "install.sh", Size: 77206, Digest: "7e9f30f4cbeefcb7b1b513943171b00d5a09ff03fe718d0dc99f1b86f096a3c2"},
			{ID: 774625226, Name: "release-index.json", Size: 609, Digest: "7c252746ef5e51484e6f8446321867ca404a872b22ecc6b40b20c727809b9c84"},
			{ID: 774625232, Name: "sbxr-linux-amd64.tar.gz", Size: 6253969, Digest: "d02d106e9914994762981357c1b70bfe8d368d02ed855885f509dab6091e2a48"},
			{ID: 774625225, Name: "sbxr-linux-arm64.tar.gz", Size: 5311325, Digest: "179bbe9aa6430f750d462fee65de5405e97817d2383d25e121882987b37b9de7"},
		},
	}, {
		Tag: "v3.1.156", Sequence: 230, ReleaseID: 453589120,
		Commit: "a65bfb6f6631077fc16ef83addc181ba32306139", RunID: "44887573881", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "e90e17a2544462bb2f542e61318951e8511c7240763b64a3d84fe24273862edb",
		QualificationManifestSHA256: "8f998a3a5fd06731ef4a8052726b27549f2fa92ca9eab0de0ea21b3a801e4934",
		Assets: []observedAsset{
			{ID: 775108288, Name: "install.sh", Size: 77206, Digest: "7baf7d1eeb1c272942736434259608ef55a8f518ec68e8eb32fe796406f02d12"},
			{ID: 775108292, Name: "release-index.json", Size: 609, Digest: "e90e17a2544462bb2f542e61318951e8511c7240763b64a3d84fe24273862edb"},
			{ID: 775108284, Name: "sbxr-linux-amd64.tar.gz", Size: 6253951, Digest: "904c53bab68dc8c5528fa2e06d3cfe1360d454f5039e861085d2fdef467851ab"},
			{ID: 775108285, Name: "sbxr-linux-arm64.tar.gz", Size: 5311282, Digest: "84c9eded7d56ce376c36b103b3ab1236ba9a811e218ac86bc574f74c1ed0094f"},
		},
	}, {
		Tag: "v3.1.157", Sequence: 231, ReleaseID: 453817808,
		Commit: "117082a372d0a88e0752b5394c152be1354fef72", RunID: "44919705888", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "00bf50aab187fe6593356d290ba2cac0b5d577f83cdaff1db52f9d9a71bd6c91",
		QualificationManifestSHA256: "85970e5ec1dd9736e48c52f67712ce80aeecff0e84d9a1e02c1e07e6608cd416",
		Assets: []observedAsset{
			{ID: 776140523, Name: "install.sh", Size: 77206, Digest: "81172be2fea33ff2c75552e6537d6066467eed161d94cac068623993d2fe806f"},
			{ID: 776140520, Name: "release-index.json", Size: 609, Digest: "00bf50aab187fe6593356d290ba2cac0b5d577f83cdaff1db52f9d9a71bd6c91"},
			{ID: 776140522, Name: "sbxr-linux-amd64.tar.gz", Size: 6254783, Digest: "d1fd6b605d68565b3a25104bb19b6a6a59d1370d1546dbb9a494bcc3fd34fff8"},
			{ID: 776140527, Name: "sbxr-linux-arm64.tar.gz", Size: 5340440, Digest: "3d9c794fcd0e46e5e042ffa9ae766ce8379e283f6f77709c3d85ea1fdcfe3faa"},
		},
	}, {
		Tag: "v3.1.158", Sequence: 232, ReleaseID: 454275266,
		Commit: "d0b1ed9a1939b14815218c33baad974b7bc6fd43", RunID: "44994457142", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "dd4077698b52304982e9de0df949eb2518fa5e3e94fbce195d04b2bfd3527536",
		QualificationManifestSHA256: "80d7cf2a3f94669c47ed90703f8a6c9681cca656c99762273e5b31bd072ae355",
		Assets: []observedAsset{
			{ID: 778254507, Name: "install.sh", Size: 77206, Digest: "e4c8101a2608d34aa13fbbecd27064f8e8008dcad2a8e9dcd023cf6e04edcf1d"},
			{ID: 778254505, Name: "release-index.json", Size: 609, Digest: "dd4077698b52304982e9de0df949eb2518fa5e3e94fbce195d04b2bfd3527536"},
			{ID: 778254509, Name: "sbxr-linux-amd64.tar.gz", Size: 6254568, Digest: "b45e3019497d831e7af7b29ab0db95a68951f0679a14007dd62b14b5d7d90a5f"},
			{ID: 778254506, Name: "sbxr-linux-arm64.tar.gz", Size: 5340609, Digest: "5b808db55f486beb8c56798d5125dc4b25ea115870fe6230e090f5c32c48926e"},
		},
	}, {
		Tag: "v3.1.159", Sequence: 233, ReleaseID: 454346483,
		Commit: "8332aa71ca6640f754369fe151c0a46e5175e15f", RunID: "45005500246", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "a6e634922685923448b6911f1267cb4fd5fd8850d1db3454c0053c0bae461b69",
		QualificationManifestSHA256: "4a456fc8f72a14aa96babf328856b7231e4fdb1fa3752614c90aeb9bfbf37934",
		Assets: []observedAsset{
			{ID: 778587127, Name: "install.sh", Size: 77206, Digest: "a9f7dd0eb0b994034515f478f1736790ff3de2157233f1a264535c33a8878c90"},
			{ID: 778587128, Name: "release-index.json", Size: 609, Digest: "a6e634922685923448b6911f1267cb4fd5fd8850d1db3454c0053c0bae461b69"},
			{ID: 778587125, Name: "sbxr-linux-amd64.tar.gz", Size: 6254660, Digest: "1a10d3aa56a5707bb5dfadb182a74a38cbb350125772a7d6797ac7b50d48171b"},
			{ID: 778587126, Name: "sbxr-linux-arm64.tar.gz", Size: 5340530, Digest: "1af5d318128f888936f648c1c416f4c8d8cebb56dee1be9270f4e892cbbb7812"},
		},
	}, {
		Tag: "v3.1.160", Sequence: 234, ReleaseID: 454438007,
		Commit: "72ddf4587dfc17f7de18f194907ba8bac2cb905d", RunID: "45019124957", SigningState: "unknown",
		ReleaseIndexSHA256: "474d62eafaa661d0c5b73c1836f4f627068aa0157154c8485ef133d0942a9546",
		Assets: []observedAsset{
			{ID: 779024353, Name: "install.sh", Size: 77206, Digest: "3fbd62cf619b26beff16c74db105cb7a0157621d72fec918f0cf8b46e0887117"},
			{ID: 779024352, Name: "release-index.json", Size: 609, Digest: "474d62eafaa661d0c5b73c1836f4f627068aa0157154c8485ef133d0942a9546"},
			{ID: 779024371, Name: "sbxr-linux-amd64.tar.gz", Size: 6254665, Digest: "72cfeb525c5e9438b8b2c67923ec74d05078fcb4a6cdea6c0bb29cec4015012e"},
			{ID: 779024358, Name: "sbxr-linux-arm64.tar.gz", Size: 5340542, Digest: "90ffcf7ea373f6a5ed65f94905595c7dd69b5291ba27113e92f44f83a2a4babe"},
		},
	}, {
		Tag: "v3.1.161", Sequence: 235, ReleaseID: 454604534,
		Commit: "1fc9e3ab05c910ad7f0614ac21212e24f50d30ac", RunID: "45042678522", SigningState: "unknown",
		ReleaseIndexSHA256: "a4a54acdd441f560e132b39b90a56fe6dbed7dfa707f082507874b54e5ec1d57",
		Assets: []observedAsset{
			{ID: 779786473, Name: "install.sh", Size: 77206, Digest: "73d272f5e57aed66961a2e8fc1b80de8201a8a88b29aa49f4f0d75d71f16fd76"},
			{ID: 779786472, Name: "release-index.json", Size: 609, Digest: "a4a54acdd441f560e132b39b90a56fe6dbed7dfa707f082507874b54e5ec1d57"},
			{ID: 779786482, Name: "sbxr-linux-amd64.tar.gz", Size: 6254637, Digest: "31f0b7c58f32bfa653020d6c5436ce875f9365fa2773cbe075c7d3f542241d02"},
			{ID: 779786457, Name: "sbxr-linux-arm64.tar.gz", Size: 5340529, Digest: "60291f7d2bd25d0b1d4906bdce314fd8d84a9fcf97977df55af9e5412e568867"},
		},
	}, {
		Tag: "v3.1.162", Sequence: 236, ReleaseID: 454999136,
		Commit: "8c29ef7a65a16ba50fa0c2020bee325ebea686af", RunID: "45108911492", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "11296eec38cd27eaae81c95b2ba684b190d3cced3f776ecba0c184499148267b",
		QualificationManifestSHA256: "d3c470c314e4dc49cf87a35d37e619bb9bf82b9582e18c5ca545e35e9918ecec",
		Assets: []observedAsset{
			{ID: 781564659, Name: "install.sh", Size: 77206, Digest: "43fcba6924849bc4ef4ecd20342a074d545e1e662779efdbc94d00abed3b1b70"},
			{ID: 781564658, Name: "release-index.json", Size: 609, Digest: "11296eec38cd27eaae81c95b2ba684b190d3cced3f776ecba0c184499148267b"},
			{ID: 781564657, Name: "sbxr-linux-amd64.tar.gz", Size: 6254562, Digest: "3df54af16298e8ea8afb18fead11a868adc3d9f6ecb14b0e4480ba75aabcb065"},
			{ID: 781564660, Name: "sbxr-linux-arm64.tar.gz", Size: 5340624, Digest: "8de68b912819567acd16e7ef4d31fb40a562396a725474ff0bf6fc14a6dc2e2f"},
		},
	}, {
		Tag: "v3.1.163", Sequence: 237, ReleaseID: 456494759,
		Commit: "9373a863a1ff9d24cb22639657d0f6fa6b9045fc", RunID: "45351436999", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "3603ea6d41d58810c4a265e30c05b8291c99d1225e301c1465c7fb7dcf871653",
		QualificationManifestSHA256: "8bd35b6a24440b29c1981b74aac490f8c245a4fe2c17ed137ce6248cce12d673",
		Assets: []observedAsset{
			{ID: 786375483, Name: "install.sh", Size: 77206, Digest: "d4957fcc4ff4a35ffc07d1f3ccf7e9bbb3600af0137e890b47bcacbf7455aa94"},
			{ID: 786375485, Name: "release-index.json", Size: 609, Digest: "3603ea6d41d58810c4a265e30c05b8291c99d1225e301c1465c7fb7dcf871653"},
			{ID: 786375480, Name: "sbxr-linux-amd64.tar.gz", Size: 6259801, Digest: "dde8bce0b7cd058846bbc9b306fa19a6856463da5a870c629ab495f69e861368"},
			{ID: 786375481, Name: "sbxr-linux-arm64.tar.gz", Size: 5333744, Digest: "2c4da2783f9fce945520e8f5576acf64b6fd373944edec866fd66b22f2ea2b34"},
		},
	}, {
		Tag: "v3.1.164", Sequence: 238, ReleaseID: 456901275,
		Commit: "5aa6c80c47c45087b844d3a48ba3f64ec31eda2d", RunID: "45407968687", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "8f0b962bb8304f5b3e5bc24fbb93d2cf83380f9c989ef760623a9f1479c42bf4",
		QualificationManifestSHA256: "10fd48951e970dc88bdf72416359836ca51496b64e47878337fcd61abded480d",
		Assets: []observedAsset{
			{ID: 787586011, Name: "install.sh", Size: 77206, Digest: "ea61f1f7243c85ab6a7ebedd7632f922abcfea69d5d41f7021c6c17e506c6f16"},
			{ID: 787586013, Name: "release-index.json", Size: 609, Digest: "8f0b962bb8304f5b3e5bc24fbb93d2cf83380f9c989ef760623a9f1479c42bf4"},
			{ID: 787586012, Name: "sbxr-linux-amd64.tar.gz", Size: 6259836, Digest: "68506b8dc3669933bef91ac85c4fbef721474d53b8030bbde0ad0a38baa14664"},
			{ID: 787586020, Name: "sbxr-linux-arm64.tar.gz", Size: 5333800, Digest: "6b93280cb98d502c1b02f5b2770d19a087eae3d3cfbd230375092335a9b5fff0"},
		},
	}, {
		Tag: "v3.1.165", Sequence: 239, ReleaseID: 457594332,
		Commit: "87d70a276ad234344b054b6cc712eb67672c7c21", RunID: "45530167834", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "223562ff78a2e12bbfb87513f3a9c1074c4cf5c92b0681d41359456a26b34f50",
		QualificationManifestSHA256: "ced229372a484edf648e5b9da47ee686a7ddb7dd29ebaa95fffd6371ee0c47c0",
		Assets: []observedAsset{
			{ID: 789808644, Name: "install.sh", Size: 77206, Digest: "6c2bd94ad8d065965115b279edcf0f5fa719230c9ef89d448a7eb8e45c2e78aa"},
			{ID: 789808649, Name: "release-index.json", Size: 609, Digest: "223562ff78a2e12bbfb87513f3a9c1074c4cf5c92b0681d41359456a26b34f50"},
			{ID: 789808647, Name: "sbxr-linux-amd64.tar.gz", Size: 6259673, Digest: "fe98f8527a2023da97399706921b1ed00fb68f3a9ea70e651610689e252594bb"},
			{ID: 789808639, Name: "sbxr-linux-arm64.tar.gz", Size: 5333882, Digest: "8f85290581c4caf8eba1c2a7f013b1ee3f393b744b2a3071341144ebac04299e"},
		},
	}, {
		Tag: "v3.1.166", Sequence: 240, ReleaseID: 458388340,
		Commit: "44e9fdb3e97cef714b470a1985c0790e88584735", RunID: "45650409988", SigningState: "unknown",
		ReleaseIndexSHA256: "cda62e7974dbbf0d7da822ecec8fbfd9adaa096f777ee7bd6a1743012e83d28e",
		Assets: []observedAsset{
			{ID: 792355354, Name: "install.sh", Size: 77206, Digest: "eb59d915dd920ca20bfb8e5b70dcb5d07684559d5a79bdd572c51a883dc2f89a"},
			{ID: 792355353, Name: "release-index.json", Size: 609, Digest: "cda62e7974dbbf0d7da822ecec8fbfd9adaa096f777ee7bd6a1743012e83d28e"},
			{ID: 792355350, Name: "sbxr-linux-amd64.tar.gz", Size: 6259742, Digest: "8c406b0a57d5d328ed50548fd604ce7ac732ef94ac890e7c4f15f24aef001cd9"},
			{ID: 792355352, Name: "sbxr-linux-arm64.tar.gz", Size: 5333972, Digest: "9258c74e6fe9431597a17b71d261e85498a5b7bfbf080586bf8547a8ad6424f0"},
		},
	}, {
		Tag: "v3.1.167", Sequence: 241, ReleaseID: 458865361,
		Commit: "c9f3c5a113f2f9c04d82b1b855ad65a82a02c9e7", RunID: "45735394188", SigningState: "signed-unqualified",
		ReleaseIndexSHA256:          "1ff37d650b62d5827fc560142b425810073d5312edaa6ed219590eea4f899cae",
		QualificationManifestSHA256: "c932e7937603d0d33b18188d60894144152374adf31b093face54945904a230d",
		Assets: []observedAsset{
			{ID: 793975047, Name: "install.sh", Size: 77206, Digest: "10da8fa9eb6238c139cc70687d9134a440354995f5243f8a599133bb7b435452"},
			{ID: 793975054, Name: "release-index.json", Size: 609, Digest: "1ff37d650b62d5827fc560142b425810073d5312edaa6ed219590eea4f899cae"},
			{ID: 793975051, Name: "sbxr-linux-amd64.tar.gz", Size: 6259793, Digest: "fd48a3a1d34dada7a1a446c75f775f853e3002cc532a662c023107e8c8e3f883"},
			{ID: 793975050, Name: "sbxr-linux-arm64.tar.gz", Size: 5333733, Digest: "1d93f2ea92294a5ae174d5adb80f1b6e53a7583845497f2c736cece52a48ee72"},
		},
	}, {
		Tag: "v3.1.168", Sequence: 242, ReleaseID: 459027331,
		Commit: "ac196038260b80ed985581b71b0b3c358e30c413", RunID: "45758998511", SigningState: "unknown",
		ReleaseIndexSHA256: "e8c8ba06f60f3185932d7099b9a705b58f096c4e873c215dbcdbc667c59a6ee3",
		Assets: []observedAsset{
			{ID: 794569345, Name: "install.sh", Size: 77206, Digest: "4e3eeaada37c192cb47864ebcc225da7c0e55b1e353f9ec525abeca8131b3124"},
			{ID: 794569340, Name: "release-index.json", Size: 609, Digest: "e8c8ba06f60f3185932d7099b9a705b58f096c4e873c215dbcdbc667c59a6ee3"},
			{ID: 794569342, Name: "sbxr-linux-amd64.tar.gz", Size: 6259901, Digest: "c5311ad6fc0620093da8186b03fdab29e0219e605861c96a259a993f4fac44b3"},
			{ID: 794569346, Name: "sbxr-linux-arm64.tar.gz", Size: 5333799, Digest: "4f26c3e84b33253099500b8fdb56edd28b800a3e1062e3dcab59ba9e47fb2cb8"},
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
	// The Owner-approved exception is exactly these forty retained identities.
	if len(policy) != 40 || observed.Releases == nil || len(observed.Refs) != len(policy) {
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
