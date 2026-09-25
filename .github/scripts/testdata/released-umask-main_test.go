// Copied into a disposable v3.1.81 source tree ONLY for the wrapper rehearsal.
// It selects existing real lifecycle tests with their synthetic release/runtime
// seams. It is not part of SBXR and never produces packaged/live evidence.
package softwarelifecycle

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "Umask:") {
			fmt.Println(line)
		}
	}
	flag.Set("test.run", "^(TestUpdateInstallsFreshQualifiedHigherSequenceThroughPublicInterface|TestUpdateFailureAfterPreparedRestoresVerifiedPriorPair|TestUpdateRestoresPriorWhileTheRollbackLinkStillHasTwoLinks|TestCommittedUpdateRetainsAuthorityUntilRuntimeCompletion)$")
	flag.Set("test.v", "true")
	os.Exit(m.Run())
}
