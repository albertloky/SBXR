package ownerconsole

// Scenario is typed presentation input for the approved Style A fixtures.
// Outcome Modules supply these facts; Owner Console only presents them.
type Scenario uint8

const (
	PrivacyChoice Scenario = iota
	AuthenticatedOverview
	DedicatedAccess
	LimitedDashboard
	InstallationReview
	CloudflareWalkthrough
	CorrectionFlow
	MeasuredDownload
	UnknownCloudflareVerification
	MultiStepChangeSet
	CancellationRequested
	RecoveryWithRollback
	RecoveryWithoutRecovery
	UpdateReview
	CompleteRemovalConfirmation
	ForwardOnlyRemoval
	UndersizedPause
	ConnectionProfilesScreen
	CertificatesScreen
	SubscriptionScreen
	NetworkScreen
	ServicesDiagnosticsScreen
	SecurityScreen
	LiveProfileCheckScreen
)

type navigationID uint8

const (
	overviewNavigation navigationID = iota
	accessNavigation
	profilesNavigation
	cloudflareNavigation
	certificatesNavigation
	subscriptionNavigation
	networkNavigation
	servicesNavigation
	updatesNavigation
	securityNavigation
	removalNavigation
	exitNavigation
)

type navigationItem struct {
	id       navigationID
	label    string
	scenario Scenario
	exit     bool
}

type limitedAction uint8

const (
	retryAuthentication limitedAction = iota
	viewSafeDiagnostics
	exitLimitedDashboard
)

type limitedActionDefinition struct {
	label  string
	action limitedAction
}

var limitedActions = [...]limitedActionDefinition{
	{label: "Authenticate again", action: retryAuthentication},
	{label: "View secret-safe diagnostics", action: viewSafeDiagnostics},
	{label: "Exit SBXR", action: exitLimitedDashboard},
}

var navigation = []navigationItem{
	{id: overviewNavigation, label: "Overview", scenario: AuthenticatedOverview},
	{id: accessNavigation, label: "Access", scenario: DedicatedAccess},
	{id: profilesNavigation, label: "Connection Profiles", scenario: ConnectionProfilesScreen},
	{id: cloudflareNavigation, label: "Cloudflare Tunnel", scenario: CloudflareWalkthrough},
	{id: certificatesNavigation, label: "Certificates", scenario: CertificatesScreen},
	{id: subscriptionNavigation, label: "Subscription", scenario: SubscriptionScreen},
	{id: networkNavigation, label: "Network", scenario: NetworkScreen},
	{id: servicesNavigation, label: "Services and diagnostics", scenario: ServicesDiagnosticsScreen},
	{id: updatesNavigation, label: "Updates", scenario: UpdateReview},
	{id: securityNavigation, label: "Security", scenario: SecurityScreen},
	{id: removalNavigation, label: "Complete removal", scenario: CompleteRemovalConfirmation},
	{id: exitNavigation, label: "Exit SBXR", exit: true},
}

type fixture struct {
	header       string
	title        string
	lines        []string
	details      []string
	navigation   navigationID
	allowsBack   bool
	acceptsInput bool
	inputLine    int
	progress     ProgressKind
}

var scenarioFixtures = map[Scenario]fixture{
	PrivacyChoice: {
		header: "Not installed - privacy choice", title: "PRIVACY BEFORE ACCESS", navigation: overviewNavigation,
	},
	AuthenticatedOverview: {
		header: "Managed - rev 42 - authenticated", title: "OVERVIEW", navigation: overviewNavigation,
		lines:   []string{"All six Connection Profiles are Healthy.", "", "CONNECTION PROFILES", "[HEALTHY] REALITY Vision             443/TCP", "[HEALTHY] XHTTP Cloudflare           xhttp.example.test", "[HEALTHY] WebSocket Cloudflare       ws.example.test", "[HEALTHY] Hysteria2                  443/UDP", "[HEALTHY] TUIC                       8443/UDP", "[HEALTHY] AnyTLS                     9443/TCP", "", "CLIENT ACCESS", "> Open Access", "  Run Live Profile Check", "", "Access values have their own menu and privacy warning."},
		details: []string{"SYSTEM DETAILS", "", "VPS        203.0.113.10", "Uptime     18 days", "Last check 2 minutes ago", "", "RECENT ACTIVITY", "", "[DONE] Health check passed", "[DONE] Certificate renewed", "- No active Change Set"},
	},
	DedicatedAccess: {
		header: "Managed - rev 42 - authenticated", title: "CLIENT ACCESS VALUES", navigation: accessNavigation, allowsBack: true,
		lines:   []string{"Client Access Values require this launch's privacy choice", "and successful system authentication.", "", "No value is available in a limited or unprivileged session.", "", "Access never depends on PgDn."},
		details: []string{"PRIVACY", "", "Values may remain in:", "- terminal scrollback", "- clipboard history", "- synchronized clipboards", "- screen recordings"},
	},
	LimitedDashboard: {
		header: "Managed - rev 42 - limited", title: "LIMITED DASHBOARD", navigation: overviewNavigation,
		lines:   []string{"Sudo authentication was denied or cancelled.", "", "[HEALTHY] Installation lineage proven - revision 42", "[HEALTHY] 6 Modules Healthy - 0 Failed - 0 Unknown", "[HEALTHY] Last secret-safe inspection 2 minutes ago", "", "Client Access Values                 HIDDEN", "Privileged actions                  UNAVAILABLE", "", "Nothing failed and no Change Set began.", ""},
		details: []string{"DETAILS", "", "Safe read-only facts remain available.", "No Change Set began."},
	},
	InstallationReview: {
		header: "Not installed - unprivileged", title: "REVIEW INSTALLATION PLAN", navigation: overviewNavigation, allowsBack: true,
		lines:   []string{"Download, verification and unprivileged preflight passed.", "", "Release    v1.0.0 - commit 7ca1... - index 48ab...", "Files      1 executable - 11 embedded Modules", "Services   4 services - 3 timers", "Ports      SSH, 443 TCP+UDP, 8443, 9443, 10443", "Disk       3.8 GiB free after reservation", "Rollback   Automatic until durable Complete", "", "Apply will show the normal system sudo prompt,", "recheck volatile facts, then start one Change Set.", "", "> Apply installation", "  Back and edit", "  Save non-secret draft", "", "Esc changes nothing - Enter opens sudo prompt"},
		details: []string{"PLAN", "", "Required checks passed.", "Rollback remains available until durable Complete."},
	},
	CloudflareWalkthrough: {
		header: "Not installed - unprivileged", title: "CLOUDFLARE TOKEN - STEP 3 OF 5", navigation: cloudflareNavigation, allowsBack: true,
		lines:   []string{"dash.cloudflare.com/profile/api-tokens", "My Profile > API Tokens > Create Token", "> Create Custom Token", "", "Name       SBXR - selected account / selected zone", "Account    Cloudflare Tunnel                 Edit", "Zone       DNS                               Edit", "Resources  Include > Specific account > selected", "           Include > Specific zone > selected", "", "Continue to summary > Create Token > copy once", "", "Scoped token (masked, memory-only):", "> ********", "", "> Verify token", "  Back and continue later"},
		details: []string{"MINIMUM AUTHORITY", "", "Specific account", "Specific zone", "No Global API Key", "Token remains memory-only"},
	},
	CorrectionFlow: {
		header: "Not installed - unprivileged", title: "CORRECTION FLOW - NET-PORT-004", navigation: networkNavigation, allowsBack: true, acceptsInput: true, inputLine: 9,
		lines:   []string{"PROBLEM   9443/TCP is already in use", "FOUND     caddy.service - 0.0.0.0:9443/TCP", "REQUIRED  available public TCP port for AnyTLS", "", "WHY SBXR STOPPED", "Overwriting an unrelated listener could break it.", "There is no Continue anyway.", "", "Optional preferred port (1024-65535):", "> -", "", "> Fix with SBXR - choose and prove a safe port", "  Check again", "  Back", "", "No mutation has begun."},
		details: []string{"SAFE EVIDENCE", "", "NET-PORT-004", "No mutation has begun.", "Evidence is redacted."},
	},
	MeasuredDownload: {
		header: "Change in progress - rev 42 - authenticated", title: "DOWNLOAD RELEASE v1.1.0", navigation: updatesNavigation, progress: MeasuredProgress,
		lines:   []string{"The file size is known, so SBXR shows real progress.", "", "Downloading  [========------------]  42%", "26.4 MiB of 62.9 MiB - 8.2 MiB/s", "", "The signature is verified after the download.", "", "> Request cancellation", "  Close TUI"},
		details: []string{"WHY A BAR?", "", "Downloaded bytes and total", "bytes are both known.", "", "The percentage is measured,", "not estimated."},
	},
	UnknownCloudflareVerification: {
		header: "Checking - rev 42 - authenticated", title: "CHECK CLOUDFLARE CONNECTION", navigation: cloudflareNavigation, progress: UnknownProgress,
		lines:   []string{"The provider decides how long this takes.", "", "* Verifying tunnel route...       00:18", "", "No percentage is shown because SBXR cannot know it.", "", "> Request cancellation", "  Close TUI"},
		details: []string{"WHY A SPINNER?", "", "SBXR knows the check is", "alive, but not how much work", "the provider has left.", "", "Elapsed time stays visible."},
	},
	MultiStepChangeSet: {
		header: "Change in progress - rev 42 - authenticated", title: "UPDATE TO v1.1.0 - 00:01:42", navigation: updatesNavigation, progress: MixedStepProgress,
		lines:   []string{"The global mutation lock is held by Change Set 01J8...", "", "[DONE] Prepared", "[DONE] Release switched", "[NOW] Validate prepared sing-box configuration", "      [===========---------]  54%", "[NEXT] Pre-publication health", "[NEXT] Publish Desired State revision 43", "[NEXT] Post-publication health", "[NEXT] Complete", "", "Current Desired State remains revision 42.", "Closing the TUI or losing SSH does not stop work.", "", "> Request cancellation", "  Close TUI", "  View safe evidence"},
		details: []string{"CHANGE SET 01J8...", "", "2 of 7 steps complete", "Step 3 is measurable: 54%", "", "Current revision  42", "Target revision   43", "", "Safe cancellation checkpoint", "after validation."},
	},
	CancellationRequested: {
		header: "Change in progress - rev 42 - authenticated", title: "CANCELLATION REQUESTED - 00:01:51", navigation: updatesNavigation,
		lines:   []string{"SBXR will not kill an unsafe step midway.", "", "[DONE] Cancellation requested - durable", "[NOW] Finish configuration validation", "[NEXT] Record next safe checkpoint", "[NEXT] Automatic rollback to revision 42", "[NEXT] Prove rollback", "[NEXT] Return to Managed", "", "Closing the TUI or losing SSH changes nothing.", "Automatic rollback cannot be cancelled.", "", "> Close TUI", "  View safe evidence"},
		details: []string{"CANCELLATION", "", "Request is durable.", "Rollback begins at the next safe checkpoint."},
	},
	RecoveryWithRollback: {
		header: "Recovery Required - rev 42 - authenticated", title: "AUTOMATIC ROLLBACK IS AVAILABLE", navigation: servicesNavigation,
		lines:   []string{"SYS-LINEAGE-011 - normal mutations are blocked.", "", "Last proven State     Managed - revision 42", "Unfinished Change Set 01J8... update to v1.1.0", "Journal               Valid", "Rollback Snapshot     Valid and checksum-proven", "Affected service      sing-box stopped", "", "Retry only runs the rollback authorized by the", "original approved Plan. It cannot change the target.", "", "> Retry automatic rollback", "  View safe evidence", "  Check again", "  Read-only dashboard", "  Complete removal"},
		details: []string{"RECOVERY MATERIAL", "", "Last proven revision 42", "Unfinished Change Set 01J8...", "Retry uses the original approved target."},
	},
	RecoveryWithoutRecovery: {
		header: "Recovery Required - rev ? - authenticated", title: "THIS INSTALLATION CANNOT BE RECOVERED", navigation: servicesNavigation,
		lines:   []string{"SYS-LINEAGE-019 - normal mutations are blocked.", "", "Desired State         missing", "Rollback Snapshot     checksum cannot be proven", "Automatic rollback    UNAVAILABLE", "", "SBXR cannot adopt files, force services, bypass the", "journal, restore an old revision, or recreate secrets.", "", "Complete removal, then rebuild from scratch.", "", "> View safe evidence", "  Read-only diagnostics", "  Check again", "  Complete removal", "", "Retry automatic rollback is intentionally absent."},
		details: []string{"REBUILD REQUIRED", "", "No adoption or force-start.", "Complete removal then Clean-VPS rebuild."},
	},
	UpdateReview: {
		header: "Managed - rev 42 - authenticated", title: "REVIEW UPDATE PLAN", navigation: updatesNavigation, allowsBack: true,
		lines:   []string{"Discovery and verification changed nothing.", "", "Installed    v1.0.0 - sequence 12 - revision 42", "Candidate    v1.1.0 - sequence 13 - immutable", "Migration    schema 4 > 5 - reviewed and complete", "Interruption sing-box restarts briefly", "Rollback     active Change Set only", "", "Apply rebuilds a fresh one-use Plan. The previous", "release is deleted after durable Complete.", "", "> Apply update", "  View every changed file and service", "  Not now"},
		details: []string{"RELEASE IDENTITIES", "", "Installed sequence 12", "Candidate sequence 13", "Rollback returns to installed identity."},
	},
	CompleteRemovalConfirmation: {
		header: "Managed - rev 42 - authenticated", title: "COMPLETE REMOVAL - PERMANENT", navigation: removalNavigation, allowsBack: true,
		lines:   []string{"Removes State, secrets, certificates, releases,", "services, identities, listeners, and SBXR firewall.", "", "Client copies may remain. A virtual VPS cannot promise", "physical secure erasure.", "", "Before Irreversible removal started: rollback possible.", "After it: no cancellation, restore, or Back.", "", "Type exactly: COMPLETE REMOVAL", "> -", "", "- Permanently remove SBXR  [locked]", "  Back", "", "Ordinary Enter or partial pasted text cannot confirm."},
		details: []string{"TWO OWNER ACTS", "", "Exact text first", "Separate selection second", "", "Cloudflare token revocation", "remains Albert's step."},
	},
	ForwardOnlyRemoval: {
		header: "Change in progress - authenticated", title: "IRREVERSIBLE REMOVAL STARTED", navigation: removalNavigation,
		lines:   []string{"Cancellation and restore are no longer possible.", "Restart continues deletion in this fixed order.", "", "[DONE] Public exposure removed and verified", "[DONE] Irreversible removal started - durable", "[NOW] Delete Desired State and secrets", "[NEXT] Delete certificates and releases", "[NEXT] Delete services and identities", "[NEXT] Delete SBXR nftables table", "[NEXT] Delete removal runner and journal last", "[NEXT] Prove Not installed", "", "No Back action. No cancellation action.", "", "> View forward-only progress"},
		details: []string{"FORWARD-ONLY", "", "Delete runner and journal last", "Prove Not installed", "No Back or cancellation"},
	},
	UndersizedPause: {
		header: "Screen paused - rev 42 - authenticated", title: "TERMINAL IS TOO SMALL", navigation: networkNavigation,
		lines:   []string{"", "Required   80 columns x 24 rows", "Current    72 columns x 20 rows", "", "The current screen, input and selection are preserved.", "Nothing was approved, discarded, or partly redrawn.", "", "Enlarge the terminal to continue.", "", "> Exit SBXR"},
		details: []string{"PAUSED", "", "Drawing is paused.", "Enlarge the terminal to resume."},
	},
	ConnectionProfilesScreen: {
		title: "CONNECTION PROFILES", navigation: profilesNavigation, allowsBack: true,
		lines:   []string{"[HEALTHY] REALITY Vision", "[HEALTHY] XHTTP Cloudflare", "[HEALTHY] WebSocket Cloudflare", "[HEALTHY] Hysteria2", "[HEALTHY] TUIC", "[HEALTHY] AnyTLS", "", "> Open selected Connection Profile"},
		details: []string{"Six fixed Connection Profiles", "No protocol or node aliases"},
	},
	CertificatesScreen: {
		title: "CERTIFICATES", navigation: certificatesNavigation, allowsBack: true,
		lines:   []string{"[HEALTHY] IP certificate", "[HEALTHY] Domain certificate", "", "> Review certificate facts"},
		details: []string{"Private keys never render.", "Renewal uses the owning Module."},
	},
	SubscriptionScreen: {
		title: "SUBSCRIPTION", navigation: subscriptionNavigation, allowsBack: true,
		lines:   []string{"[HEALTHY] Published representations", "", "> Open subscription facts", "  Open Access to copy the URL"},
		details: []string{"Seven named representations", "Client Access Values remain in Access."},
	},
	NetworkScreen: {
		title: "NETWORK", navigation: networkNavigation, allowsBack: true,
		lines:   []string{"[HEALTHY] SBXR-owned listeners", "[HEALTHY] SBXR nftables table", "", "> Review network facts"},
		details: []string{"Unowned resources are never adopted.", "Provider firewall remains manual."},
	},
	ServicesDiagnosticsScreen: {
		title: "SERVICES AND DIAGNOSTICS", navigation: servicesNavigation, allowsBack: true,
		lines:   []string{"[HEALTHY] Managed services", "[HEALTHY] Scheduled checks", "", "> Run typed read-only Check", "  Build support bundle"},
		details: []string{"Raw logs and commands never render.", "Recovery Required remains a separate status."},
	},
	SecurityScreen: {
		title: "SECURITY", navigation: securityNavigation, allowsBack: true,
		lines:   []string{"Owner Console runs non-root.", "Infrastructure Secrets never render or copy.", "", "> Review privacy and access boundaries"},
		details: []string{"One Owner", "Short-lived validated privilege", "No telemetry or automatic uploads"},
	},
	LiveProfileCheckScreen: {
		title: "LIVE PROFILE CHECK", navigation: subscriptionNavigation, allowsBack: true,
		lines:   []string{"Session-only Live Profile Check is waiting for typed facts.", "", "> Back"},
		details: []string{"MEMORY ONLY", "", "No traffic history is retained."},
	},
}

func scenarioFixture(scenario Scenario) fixture { return scenarioFixtures[scenario] }
