package ownerconsole

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type profilesStub struct {
	outcomeStub
	view               ProfilesPresentation
	profileReviews     map[ProfileChange]ChangeReview
	profileChanges     []ProfileChangeRequest
	profileReviewDelay time.Duration
	validation         ProfileValidation
	validationProfile  []AccessProfileID
	validationDelay    time.Duration
	clientReviews      map[ClientAccessChange]ChangeReview
	clientChanges      []ClientAccessChange
	live               LiveProfileCheckPresentation
	liveCalls          int
	liveDelay          time.Duration
	liveReplies        []LiveProfileCheckPresentation
	liveUpdates        []LiveProfileCheckPresentation
	liveUpdateDelay    time.Duration
	nilLive            bool
	nonClosingLive     bool
	lateLiveRelease    chan struct{}
	liveStarted        chan struct{}
	liveCancelled      chan struct{}
}

func (stub *profilesStub) ViewProfiles(context.Context) ProfilesPresentation { return stub.view }
func (stub *profilesStub) ReviewProfileChange(_ context.Context, request ProfileChangeRequest) ChangeReview {
	time.Sleep(stub.profileReviewDelay)
	stub.profileChanges = append(stub.profileChanges, request)
	return stub.profileReviews[request.Change]
}
func (stub *profilesStub) ValidateProfile(_ context.Context, profile AccessProfileID) ProfileValidation {
	time.Sleep(stub.validationDelay)
	stub.validationProfile = append(stub.validationProfile, profile)
	return stub.validation
}

func TestRunReviewsEachCompleteProfileChangeWithoutStartingIt(t *testing.T) {
	for _, test := range []struct {
		name         string
		profile      int
		action       int
		change       ProfileChange
		planIdentity PlanIdentity
	}{
		{name: "rotate one", action: 1, change: RotateProfileCredential, planIdentity: "rotate-one-profile"},
		{name: "disable", action: 3, change: DisableProfile, planIdentity: "disable-profile"},
		{name: "enable", profile: 5, action: 3, change: EnableProfile, planIdentity: "enable-profile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &profilesStub{view: completeProfilesPresentation(), profileReviews: map[ProfileChange]ChangeReview{test.change: completePlan(test.planIdentity)}}
			keys := strings.Repeat("\x1b[B", test.profile) + strings.Repeat("\x1b[C", test.action) + "\r"
			got := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: stub, ProfileOutcomes: stub}, 120, 36, "", keys, "", "\x03\r")
			want := ProfileChangeRequest{Profile: AccessProfileID(test.profile + 1), Change: test.change}
			if len(stub.profileChanges) != 1 || stub.profileChanges[0] != want || len(stub.applyPlans) != 0 || !strings.Contains(got, string(test.planIdentity)) || !strings.Contains(got, "PLAN 1 OF") {
				t.Fatalf("%s did not produce only its separate reviewed Plan: requests=%#v applies=%#v\n%s", test.name, stub.profileChanges, stub.applyPlans, got)
			}
		})
	}
}

func TestRunShowsOnlyTheTypedNativeValidationResult(t *testing.T) {
	stub := &profilesStub{view: completeProfilesPresentation(), validation: ProfileValidation{Profile: TUICProfile, Health: ProfileHealthy, Code: "CONNECTION-PROFILES-TUIC-NATIVE-VALID"}}
	keys := strings.Repeat("\x1b[B", 4) + strings.Repeat("\x1b[C", 2) + "\r"
	got := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: stub, ProfileOutcomes: stub}, 80, 24, "", keys, "", "\x03\r")
	if len(stub.validationProfile) != 1 || stub.validationProfile[0] != TUICProfile || !strings.Contains(got, "Native validation HEALTHY") || !strings.Contains(got, "CONNECTION-PROFILES-TUIC-NATIVE-VALID") || len(stub.applyPlans) != 0 {
		t.Fatalf("native validation was not rendered as a read-only typed result\n%s", got)
	}
}

func TestRunOpensOnlyTheSelectedProfileInAuthenticatedAccess(t *testing.T) {
	stub := &profilesStub{view: completeProfilesPresentation()}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 2) + "\r", "", "\x1b[B\r", "", "\x03\r"}
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	if !strings.Contains(got, "CLIENT-XHTTP-MARKER") || strings.Contains(got, "CLIENT-REALITY-MARKER") {
		t.Fatalf("Open in Access did not focus only the selected profile\n%s", got)
	}
}

func (stub *profilesStub) ReviewClientAccessChange(_ context.Context, change ClientAccessChange) ChangeReview {
	stub.clientChanges = append(stub.clientChanges, change)
	return stub.clientReviews[change]
}

func TestRunShowsNamedSubscriptionCountsAndOmissionsWithoutValues(t *testing.T) {
	stub := &profilesStub{view: completeProfilesPresentation()}
	got := runTranscriptSteps(t, Session{Scenario: SubscriptionScreen, Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, "", "\x03\r")
	for _, want := range []string{"subscription URL 5/6", "v2rayN 5/6", "Shadowrocket 5/6", "Karing 4/6 - XHTTP - Not offered - AnyTLS - Disabled", "Mihomo 5/6", "sing-box 4/6 - XHTTP - Not offered - AnyTLS - Disabled", "Open Access", "Rotate all", "Rotate subscription token only", "Revoke all client access", "Run Live Profile Check"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Subscription view omitted %q\n%s", want, got)
		}
	}
	if strings.Contains(got, "CLIENT-SUBSCRIPTION-MARKER") || strings.Contains(got, "CLIENT-SHADOWROCKET-MARKER") {
		t.Fatalf("Subscription view rendered a Client Access Value outside Access\n%s", got)
	}
}

func TestRunReviewsDistinctRotateAllTokenOnlyAndRevokeAllChangeSets(t *testing.T) {
	for _, test := range []struct {
		name    string
		action  int
		change  ClientAccessChange
		plan    PlanIdentity
		effects []string
	}{
		{name: "Rotate all", action: 1, change: RotateEveryProfileCredential, plan: "rotate-all-six-credentials", effects: []string{"Six profile credentials replaced", "Subscription token remains unchanged"}},
		{name: "subscription token only", action: 2, change: RotateSubscriptionToken, plan: "rotate-subscription-token", effects: []string{"Subscription token replaced", "Six profile credentials remain unchanged"}},
		{name: "Revoke all client access", action: 3, change: RevokeAllClientAccess, plan: "revoke-all-client-access", effects: []string{"Subscription token replaced", "Six profile credentials replaced", "Every representation replaced", "No dual-credential grace"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			review := completePlan(test.plan)
			review.Plan.Effects = test.effects
			stub := &profilesStub{view: completeProfilesPresentation(), clientReviews: map[ClientAccessChange]ChangeReview{test.change: review}}
			got := runTranscriptSteps(t, Session{Scenario: SubscriptionScreen, Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 120, 36, "", strings.Repeat("\x1b[B", test.action)+"\r", "", "\x03\r")
			if len(stub.clientChanges) != 1 || stub.clientChanges[0] != test.change || len(stub.applyPlans) != 0 || !strings.Contains(got, string(test.plan)) {
				t.Fatalf("%s was not a distinct reviewed Change Set: requests=%#v applies=%#v\n%s", test.name, stub.clientChanges, stub.applyPlans, got)
			}
			for _, effect := range test.effects {
				if !strings.Contains(got, effect) {
					t.Fatalf("%s omitted exact effect %q\n%s", test.name, effect, got)
				}
			}
		})
	}
}

func TestRunRefusesUnsafeProfileAndLiveCheckFacts(t *testing.T) {
	unsafeProfiles := completeProfilesPresentation()
	unsafeProfiles.Profiles[0].Address = "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"
	profileOutput := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: &profilesStub{view: unsafeProfiles}}, 80, 24, "", "\x03\r")
	if strings.Contains(profileOutput, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(profileOutput, "Profile facts are unavailable") {
		t.Fatalf("unsafe profile facts crossed the Run boundary\n%s", profileOutput)
	}
	unsafeValidation := &profilesStub{view: completeProfilesPresentation(), validation: ProfileValidation{Profile: RealityVisionProfile, Health: ProfileFailed, Code: "INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"}}
	validationOutput := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: unsafeValidation, ProfileOutcomes: unsafeValidation}, 80, 24, "", strings.Repeat("\x1b[C", 2)+"\r", "", "\x03\r")
	if strings.Contains(validationOutput, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(validationOutput, "OWNER-CONSOLE-PROFILE-VALIDATION-UNAVAILABLE") {
		t.Fatalf("unsafe native-validation facts crossed the Run boundary\n%s", validationOutput)
	}

	unsafeLive := completeLiveProfileCheck()
	unsafeLive.TemporaryURL = "https://example.test/INFRASTRUCTURE-SECRET-MARKER-COMPLETE-TOKEN"
	stub := &profilesStub{view: completeProfilesPresentation(), live: unsafeLive}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "\x03\r"}
	liveOutput := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	if strings.Contains(liveOutput, "INFRASTRUCTURE-SECRET-MARKER") || !strings.Contains(liveOutput, "Live Profile Check facts are unavailable") {
		t.Fatalf("unsafe Live Profile Check facts crossed the Run boundary\n%s", liveOutput)
	}
}

func TestRunUnavailableSubscriptionHasNoHiddenActions(t *testing.T) {
	stub := &profilesStub{view: completeProfilesPresentation(), clientReviews: map[ClientAccessChange]ChangeReview{RotateEveryProfileCredential: completePlan("hidden-rotate")}}
	got := runTranscriptSteps(t, Session{Scenario: SubscriptionScreen, Profiles: stub, ProfileOutcomes: stub}, 80, 24, "", "\x1b[B\r", "", "\x03\r")
	if len(stub.clientChanges) != 0 || !strings.Contains(got, "Subscription facts are unavailable") || strings.Contains(got, "hidden-rotate") {
		t.Fatalf("an unavailable Subscription screen executed a hidden action\n%s", got)
	}
}

func TestRunProfileAndSubscriptionPlanBackRestoreTheirSelection(t *testing.T) {
	for _, test := range []struct {
		name     string
		scenario Scenario
		keys     string
		changes  func(*profilesStub) int
	}{
		{name: "profile", scenario: ConnectionProfilesScreen, keys: "\x1b[C\r", changes: func(stub *profilesStub) int { return len(stub.profileChanges) }},
		{name: "subscription", scenario: SubscriptionScreen, keys: "\x1b[B\r", changes: func(stub *profilesStub) int { return len(stub.clientChanges) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &profilesStub{view: completeProfilesPresentation(), profileReviews: map[ProfileChange]ChangeReview{RotateProfileCredential: completePlan("profile-back")}, clientReviews: map[ClientAccessChange]ChangeReview{RotateEveryProfileCredential: completePlan("subscription-back")}}
			steps := []string{"", test.keys, "", "\x1b[27u", "", "\r", "", "\x03\r"}
			_ = runTranscriptSteps(t, Session{Scenario: test.scenario, Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 120, 36, steps...)
			if stub.backCalls != 1 || test.changes(stub) != 2 {
				t.Fatalf("Back did not restore the %s selection: back=%d changes=%d", test.name, stub.backCalls, test.changes(stub))
			}
		})
	}
}

func (stub *profilesStub) RunLiveProfileCheck(ctx context.Context) <-chan LiveProfileCheckPresentation {
	stub.mu.Lock()
	call := stub.liveCalls
	stub.liveCalls++
	var reply LiveProfileCheckPresentation
	if len(stub.liveReplies) > call {
		reply = stub.liveReplies[call]
	}
	stub.mu.Unlock()
	if stub.nilLive {
		return nil
	}
	if stub.nonClosingLive {
		updates := make(chan LiveProfileCheckPresentation, 1)
		updates <- pendingLiveProfileCheck(completeLiveProfileCheck().TemporaryURL)
		go func() {
			<-ctx.Done()
			close(stub.liveCancelled)
		}()
		return updates
	}
	updates := make(chan LiveProfileCheckPresentation, 2)
	go func() {
		defer close(updates)
		time.Sleep(stub.liveDelay)
		if len(stub.liveReplies) > call {
			if stub.lateLiveRelease != nil {
				if call == 0 {
					<-stub.lateLiveRelease
				} else if call == 1 {
					close(stub.lateLiveRelease)
				}
			}
			updates <- pendingLiveProfileCheck(reply.TemporaryURL)
			updates <- reply
			return
		}
		if stub.liveStarted != nil {
			close(stub.liveStarted)
			<-ctx.Done()
			close(stub.liveCancelled)
			return
		}
		if len(stub.liveUpdates) != 0 {
			for index, update := range stub.liveUpdates {
				if index > 0 {
					time.Sleep(stub.liveUpdateDelay)
				}
				updates <- update
			}
			return
		}
		updates <- pendingLiveProfileCheck(stub.live.TemporaryURL)
		updates <- stub.live
	}()
	return updates
}

func completeLiveProfileCheck() LiveProfileCheckPresentation {
	var results [6]LiveProfileResult
	for index := range results {
		results[index] = LiveProfileResult{Profile: AccessProfileID(index + 1), Stage: LiveProfileChecked, Authenticated: true, Uplink: true, Downlink: true}
	}
	return LiveProfileCheckPresentation{TemporaryURL: "https://test/LIVE-TEMP-MARKER", Results: results, Complete: true}
}

func pendingLiveProfileCheck(url string) LiveProfileCheckPresentation {
	var results [6]LiveProfileResult
	for index := range results {
		results[index] = LiveProfileResult{Profile: AccessProfileID(index + 1), Stage: LiveProfilePending}
	}
	return LiveProfileCheckPresentation{TemporaryURL: url, Results: results}
}

func TestRunLiveProfileCheckRequiresPrivacyChoiceAndShowsAutomaticPerProfileTraffic(t *testing.T) {
	blocked := &profilesStub{view: completeProfilesPresentation(), live: completeLiveProfileCheck()}
	blockedOutput := runTranscriptSteps(t, Session{Scenario: SubscriptionScreen, Profiles: blocked, ProfileOutcomes: blocked, Access: profileClientAccessPresentation()}, 80, 24, "", strings.Repeat("\x1b[B", 4)+"\r", "", "\x03\r")
	if blocked.liveCalls != 0 || strings.Contains(blockedOutput, "LIVE-TEMP-MARKER") {
		t.Fatalf("Live Profile Check started before this launch's Client Access privacy choice\n%s", blockedOutput)
	}

	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		t.Run(fmt.Sprintf("%dx%d", size.width, size.height), func(t *testing.T) {
			stub := &profilesStub{view: completeProfilesPresentation(), live: completeLiveProfileCheck()}
			steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "\x1b[27u", "", "\x03\r"}
			got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, size.width, size.height, steps...)
			if stub.liveCalls != 1 {
				t.Fatalf("Live Profile Check calls = %d", stub.liveCalls)
			}
			for _, want := range []string{"LIVE PROFILE CHECK", "LIVE-TEMP-MARKER", "REALITY Vision", "XHTTP", "WebSocket", "Hysteria2", "TUIC", "AnyTLS", "Session-only and memory-only", "No manual success"} {
				if !strings.Contains(got, want) {
					t.Fatalf("Live Profile Check omitted %q\n%s", want, got)
				}
			}
			if strings.Count(got, "auth=yes up=yes down=yes") < 6 {
				t.Fatalf("Live Profile Check did not complete all six automatic results\n%s", got)
			}
			if size.width == 80 && !strings.Contains(got, "QR omitted at this size") {
				t.Fatalf("minimum-size Live Profile Check did not keep exact text when QR was omitted\n%s", got)
			}
			if size.width == 120 && !strings.Contains(got, "QR - same temporary test URL") {
				t.Fatalf("large Live Profile Check omitted its same-source QR\n%s", got)
			}
		})
	}
}

func TestRunLiveProfileCheckShowsURLAndAutomaticProgressWhileRunning(t *testing.T) {
	initial := pendingLiveProfileCheck(completeLiveProfileCheck().TemporaryURL)
	final := completeLiveProfileCheck()
	stub := &profilesStub{view: completeProfilesPresentation(), liveUpdates: []LiveProfileCheckPresentation{initial, final}, liveUpdateDelay: 1100 * time.Millisecond}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", ""}
	for range 30 {
		steps = append(steps, "")
	}
	steps = append(steps, "\x03\r")
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 120, 36, steps...)
	for _, want := range []string{"LIVE-TEMP-MARKER", "QR - same temporary test URL", "REALITY Vision PENDING", "AnyTLS PENDING", "Running 00:00", "Running 00:01", "Complete"} {
		if !strings.Contains(got, want) {
			t.Fatalf("staged Live Profile Check omitted %q\n%s", want, got)
		}
	}
	if strings.Count(got, "auth=yes up=yes down=yes") < 6 {
		t.Fatalf("staged Live Profile Check did not complete all six automatic results\n%s", got)
	}
}

func TestRunRefusesInvalidLiveProfileCheckStreams(t *testing.T) {
	initial := pendingLiveProfileCheck("https://test/LIVE-SEQUENCE")
	complete := completeLiveProfileCheck()
	complete.TemporaryURL = initial.TemporaryURL
	mixedInitial := initial
	mixedInitial.Results[0] = complete.Results[0]
	partial := initial
	partial.Results[0] = complete.Results[0]
	regressed := partial
	regressed.Results[0] = initial.Results[0]
	mutated := partial
	mutated.Results[0].Uplink = false

	for _, test := range []struct {
		name    string
		updates []LiveProfileCheckPresentation
	}{
		{name: "one-shot complete", updates: []LiveProfileCheckPresentation{complete}},
		{name: "mixed initial stages", updates: []LiveProfileCheckPresentation{mixedInitial}},
		{name: "checked result regresses", updates: []LiveProfileCheckPresentation{initial, partial, regressed}},
		{name: "checked result mutates", updates: []LiveProfileCheckPresentation{initial, partial, mutated}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &profilesStub{view: completeProfilesPresentation(), liveUpdates: test.updates}
			steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "", "\x03\r"}
			got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
			if !strings.Contains(got, "Live Profile Check facts are unavailable") {
				t.Fatalf("invalid Live Profile Check stream was accepted\n%s", got)
			}
		})
	}
}

func TestRunNilLiveStreamFailsSafeAndBackCancelsANonClosingStream(t *testing.T) {
	start := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", ""}
	t.Run("nil", func(t *testing.T) {
		stub := &profilesStub{view: completeProfilesPresentation(), nilLive: true}
		got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, append(start, "", "\x03\r")...)
		if !strings.Contains(got, "Live Profile Check facts are unavailable") {
			t.Fatalf("nil Live Profile Check stream did not fail safe\n%s", got)
		}
	})
	t.Run("non-closing", func(t *testing.T) {
		stub := &profilesStub{view: completeProfilesPresentation(), nonClosingLive: true, liveCancelled: make(chan struct{})}
		got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, append(start, "\x1b[27u", "", "\x03\r")...)
		select {
		case <-stub.liveCancelled:
		default:
			t.Fatalf("Back did not cancel a non-closing Live Profile Check stream\n%s", got)
		}
		if strings.Contains(got, "Live Profile Check facts are unavailable") {
			t.Fatalf("the cancelled stream replaced the restored Subscription screen\n%s", got)
		}
	})
}

func TestRunLongLiveProfileCheckURLKeepsEveryResultAndBackAtMinimumSize(t *testing.T) {
	check := completeLiveProfileCheck()
	check.TemporaryURL = "https://test/" + strings.Repeat("a", 110)
	stub := &profilesStub{view: completeProfilesPresentation(), live: check}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "\x03\r"}
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	for _, want := range []string{"REALITY Vision", "AnyTLS", "> Back"} {
		if !strings.Contains(got, want) {
			t.Fatalf("long temporary URL hid %q at minimum size\n%s", want, got)
		}
	}
	if strings.Count(got, "auth=yes up=yes down=yes") < 6 {
		t.Fatalf("long temporary URL hid an automatic result at minimum size\n%s", got)
	}
}

func TestRunBackCancelsAndErasesSessionOnlyLiveProfileCheck(t *testing.T) {
	stub := &profilesStub{view: completeProfilesPresentation(), liveStarted: make(chan struct{}), liveCancelled: make(chan struct{})}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "\x1b[27u", "", "\x03\r"}
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	select {
	case <-stub.liveCancelled:
	default:
		t.Fatalf("Back did not cancel the session-only Live Profile Check\n%s", got)
	}
	if strings.Contains(got, "Live Profile Check facts are unavailable") {
		t.Fatalf("a late cancelled result replaced the restored Subscription screen\n%s", got)
	}
}

func TestRunCompletedLiveProfileCheckWaitsBehindExitConfirmation(t *testing.T) {
	check := completeLiveProfileCheck()
	check.TemporaryURL = "https://test/EXIT-PENDING-MARKER"
	stub := &profilesStub{view: completeProfilesPresentation(), live: check, liveDelay: 80 * time.Millisecond}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "\x03", "", "", "", "", "", "\x1b[27u", "", "\x03\r"}
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	exit := strings.Index(got, "Exit SBXR?")
	result := strings.Index(got, "EXIT-PENDING-MARKER")
	afterExit := ""
	if exit >= 0 {
		afterExit = got[exit:]
	}
	complete := exit >= 0 && result >= exit && strings.Contains(afterExit, "Complete")
	for _, profile := range []string{"REALITY Vision", "XHTTP", "WebSocket", "Hysteria2", "TUIC", "AnyTLS"} {
		complete = complete && strings.Contains(afterExit, profile)
	}
	complete = complete && strings.Count(afterExit, "auth=yes up=yes down=yes") >= 6
	if !complete {
		t.Fatalf("completed Live Profile Check did not wait behind Exit confirmation and appear after Stay\n%s", got)
	}
}

func TestRunLateProfileResultsNeverMoveOrRelabelTheCurrentScreen(t *testing.T) {
	t.Run("review after Back", func(t *testing.T) {
		stub := &profilesStub{view: completeProfilesPresentation(), profileReviewDelay: 120 * time.Millisecond, profileReviews: map[ProfileChange]ChangeReview{RotateProfileCredential: completePlan("LATE-REVIEW-MARKER")}}
		got := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: stub, ProfileOutcomes: stub}, 80, 24, "", "\x1b[C\r", "\x1b[27u", "", "", "\x03\r")
		if strings.Contains(got, "LATE-REVIEW-MARKER") || !strings.Contains(got, "OVERVIEW") {
			t.Fatalf("late profile review moved the Owner after Back\n%s", got)
		}
	})

	t.Run("validation after profile change", func(t *testing.T) {
		stub := &profilesStub{view: completeProfilesPresentation(), validationDelay: 120 * time.Millisecond, validation: ProfileValidation{Profile: RealityVisionProfile, Health: ProfileHealthy, Code: "LATE-VALIDATION-MARKER"}}
		got := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: stub, ProfileOutcomes: stub}, 80, 24, "", strings.Repeat("\x1b[C", 2)+"\r", "\x1b[B", "", "", "\x03\r")
		if strings.Contains(got, "LATE-VALIDATION-MARKER") || !strings.Contains(got, "XHTTP packet-up") {
			t.Fatalf("late validation was attached to a different profile\n%s", got)
		}
	})
}

func TestRunCancelledLiveProfileCheckCannotOverwriteANewerRun(t *testing.T) {
	late, current := completeLiveProfileCheck(), completeLiveProfileCheck()
	late.TemporaryURL = "https://test/LATE-A-MARKER"
	current.TemporaryURL = "https://test/CURRENT-B-MARKER"
	stub := &profilesStub{view: completeProfilesPresentation(), liveReplies: []LiveProfileCheckPresentation{late, current}, lateLiveRelease: make(chan struct{})}
	steps := []string{"\r", "", strings.Repeat("\x1b[B", 5) + "\r", "", strings.Repeat("\x1b[B", 4) + "\r", "", "\x1b[27u", "", strings.Repeat("\x1b[B", 4) + "\r", "", "", "\x03\r"}
	got := runTranscriptSteps(t, Session{Profiles: stub, ProfileOutcomes: stub, Access: profileClientAccessPresentation()}, 80, 24, steps...)
	if stub.liveCalls != 2 || strings.Contains(got, "LATE-A-MARKER") || !strings.Contains(got, "CURRENT-B-MARKER") {
		t.Fatalf("a cancelled Live Profile Check overwrote its newer run: calls=%d\n%s", stub.liveCalls, got)
	}
}

func completeProfilesPresentation() ProfilesPresentation {
	transports := [...]string{"RAW + REALITY", "XHTTP packet-up", "WebSocket + TLS", "QUIC + TLS", "QUIC + TLS", "TCP + TLS"}
	ports := [...]uint16{443, 443, 443, 443, 8443, 9443}
	var profiles [6]ProfilePresentation
	for index := range profiles {
		profiles[index] = ProfilePresentation{
			ID: AccessProfileID(index + 1), Enabled: true,
			Service: ProfileHealthy, Listener: ProfileHealthy,
			Address: fmt.Sprintf("profile-%d.example.test", index+1), Port: ports[index], Transport: transports[index],
			Settings: "native settings reviewed",
		}
	}
	profiles[5].Enabled = false
	profiles[5].Service, profiles[5].Listener = ProfileDisabled, ProfileDisabled
	profiles[5].Published, profiles[5].Exposed = false, false
	profiles[5].CredentialRetained = true
	for index := range 5 {
		profiles[index].Published, profiles[index].Exposed = true, true
	}
	return ProfilesPresentation{Managed: true, Profiles: profiles}
}

func profileClientAccessPresentation() AccessPresentation {
	access := clientAccessPresentation()
	for index := range access.Links {
		access.Links[index].ProfileCount--
		access.Links[index].Omissions = append(access.Links[index].Omissions, AccessOmission{Profile: AnyTLSProfile, Status: Disabled})
	}
	return access
}

func TestRunShowsAllSixTypedConnectionProfilesWithOnlyCompleteActions(t *testing.T) {
	for _, size := range []struct{ width, height int }{{80, 24}, {120, 36}} {
		for index := range 6 {
			name := AccessProfileID(index + 1).String()
			t.Run(fmt.Sprintf("%dx%d/%s", size.width, size.height, name), func(t *testing.T) {
				stub := &profilesStub{view: completeProfilesPresentation()}
				got := runTranscriptSteps(t, Session{Scenario: ConnectionProfilesScreen, Profiles: stub, ProfileOutcomes: stub}, size.width, size.height, "", strings.Repeat("\x1b[B", index), "", "\x03\r")
				for _, want := range []string{name, "Service", "Listener", "Public address or hostname", "Selected port and transport", "native settings reviewed", "Open in Access", "Rotate credential", "Validate native configuration"} {
					if !strings.Contains(got, want) {
						t.Fatalf("typed Connection Profile view omitted %q\n%s", want, got)
					}
				}
				if strings.Contains(got, "Change port") || strings.Contains(got, "Repair") {
					t.Fatalf("Connection Profile exposed an incomplete action\n%s", got)
				}
				if index < 5 && !strings.Contains(got, "Disable") {
					t.Fatalf("enabled Connection Profile omitted Disable\n%s", got)
				}
				if index == 5 {
					for _, want := range []string{"DISABLED] AnyTLS", "Settings and credential retained", "Exposure CLOSED", "Publication OMITTED", "Enable"} {
						if !strings.Contains(got, want) {
							t.Fatalf("disabled Connection Profile view omitted %q\n%s", want, got)
						}
					}
					if strings.Contains(got, "[FAILED] AnyTLS") {
						t.Fatalf("deliberate disablement was presented as a health failure\n%s", got)
					}
				}
			})
		}
	}
}
