package softwarelifecycle

import "testing"

func TestOwnerExceptionIsOneCleanInstallRelease(t *testing.T) {
	support := &ReleaseSupport{Scope: FirstSubscriptionCleanInstall, Contract: SubscriptionUpdateContract, Sources: []ReleaseIdentity{}}
	if !OwnerExceptionTarget("v3.1.0", 83, support) {
		t.Fatal("approved target refused")
	}
	if OwnerExceptionTarget("v3.1.1", 83, support) || OwnerExceptionTarget("v3.1.0", 84, support) || OwnerExceptionTarget("v3.1.0", 83, nil) {
		t.Fatal("exception broadened")
	}
	support.Scope = RecurringSubscriptionUpgrade
	if OwnerExceptionTarget("v3.1.0", 83, support) {
		t.Fatal("upgrade exception granted")
	}
}
