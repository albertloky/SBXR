package ownerconsole

import (
	"context"
	"net/url"
	"strings"
	"unicode"

	qrcode "github.com/yeqown/go-qrcode/v2"
)

type AccessProfile struct {
	ShareURI string
}

type AccessLink struct {
	URL                    string
	ProfileCount           int
	Omissions              []AccessOmission
	OwnerAcceptancePending []AccessProfileID
}

type AccessProfileID uint8

const (
	RealityVisionProfile AccessProfileID = iota + 1
	XHTTPProfile
	WebSocketProfile
	Hysteria2Profile
	TUICProfile
	AnyTLSProfile
)

func (profile AccessProfileID) String() string {
	names := [...]string{"", "REALITY Vision", "XHTTP", "WebSocket", "Hysteria2", "TUIC", "AnyTLS"}
	if int(profile) >= len(names) {
		return ""
	}
	return names[profile]
}

type OmissionStatus uint8

const (
	NotOffered OmissionStatus = iota + 1
	Disabled
)

type AccessOmission struct {
	Profile AccessProfileID
	Status  OmissionStatus
}

func (omission AccessOmission) String() string {
	status := map[OmissionStatus]string{NotOffered: "Not offered", Disabled: "Disabled"}[omission.Status]
	if omission.Profile.String() == "" || status == "" {
		return ""
	}
	return omission.Profile.String() + " - " + status
}

type AccessPresentation struct {
	Profiles [6]AccessProfile
	Links    [6]AccessLink
}

type CopyResult uint8

const (
	CopyConfirmed CopyResult = iota + 1
	CopyRequested
	CopyFailed
)

type Clipboard interface {
	Copy(context.Context, string) CopyResult
}

type accessEntry struct {
	name, value            string
	profileCount           int
	omissions              []string
	candidate              bool
	ownerAcceptancePending []string
	qr                     bool
}

var accessProfileSchemes = [...]string{"vless", "vless", "vless", "hysteria2", "tuic", "anytls"}
var accessLinkNames = [...]string{"subscription URL", "v2rayN", "Shadowrocket", "Karing", "Mihomo", "sing-box"}

func (access AccessPresentation) entries() []accessEntry {
	entries := make([]accessEntry, 0, len(access.Profiles)+len(access.Links))
	for index, profile := range access.Profiles {
		if !safeURI(profile.ShareURI, accessProfileSchemes[index]) {
			return nil
		}
		entries = append(entries, accessEntry{name: AccessProfileID(index + 1).String(), value: profile.ShareURI, qr: true})
	}
	for index, link := range access.Links {
		omissions, omissionsOK := omissionFacts(link.Omissions)
		pending, pendingOK := profileFacts(link.OwnerAcceptancePending)
		candidate := index == 2
		if !safeURI(link.URL, "https") || link.ProfileCount < 0 || link.ProfileCount > 6 || !candidate && len(link.OwnerAcceptancePending) != 0 || !omissionsOK || !pendingOK {
			return nil
		}
		entries = append(entries, accessEntry{name: accessLinkNames[index], value: link.URL, profileCount: link.ProfileCount, omissions: omissions, candidate: candidate, ownerAcceptancePending: pending})
	}
	return entries
}

func safeURI(value, scheme string) bool {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Scheme != scheme || parsed.Host == "" || strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	return scheme == "https" && parsed.User == nil || scheme != "https" && parsed.User != nil
}

func omissionFacts(values []AccessOmission) ([]string, bool) {
	facts := make([]string, len(values))
	for index, value := range values {
		facts[index] = value.String()
		if facts[index] == "" {
			return nil, false
		}
	}
	return facts, true
}

func profileFacts(values []AccessProfileID) ([]string, bool) {
	facts := make([]string, len(values))
	for index, value := range values {
		facts[index] = value.String()
		if facts[index] == "" {
			return nil, false
		}
	}
	return facts, true
}

func qrLines(value string, maxWidth, maxHeight int) []string {
	code, err := qrcode.New(value)
	if err != nil {
		return nil
	}
	writer := &qrMatrixWriter{}
	if err := code.Save(writer); err != nil {
		return nil
	}
	bitmap := writer.matrix.Bitmap()
	const quiet = 4
	size := len(bitmap) + quiet*2
	if size > maxWidth || (size+1)/2 > maxHeight {
		return nil
	}
	black := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && y < len(bitmap) && x < len(bitmap[y]) && bitmap[y][x]
	}
	lines := make([]string, 0, (size+1)/2)
	for y := 0; y < size; y += 2 {
		var line strings.Builder
		for x := range size {
			switch top, bottom := black(x, y), black(x, y+1); {
			case top && bottom:
				line.WriteRune('█')
			case top:
				line.WriteRune('▀')
			case bottom:
				line.WriteRune('▄')
			default:
				line.WriteByte(' ')
			}
		}
		lines = append(lines, line.String())
	}
	return lines
}

type qrMatrixWriter struct{ matrix qrcode.Matrix }

func (writer *qrMatrixWriter) Write(matrix qrcode.Matrix) error {
	writer.matrix = *matrix.Copy()
	return nil
}
func (*qrMatrixWriter) Close() error { return nil }
