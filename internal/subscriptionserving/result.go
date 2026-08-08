package subscriptionserving

import "errors"

type HealthStatus string

const (
	Healthy        HealthStatus = "Healthy"
	NeedsAttention HealthStatus = "Needs attention"
	Failed         HealthStatus = "Failed"
	Unknown        HealthStatus = "Unknown"
)

type Failure struct {
	Code    string
	Problem string
}

func (failure *Failure) Error() string { return failure.Code + ": " + failure.Problem }

type HealthResult struct {
	Status HealthStatus
	Code   string
}

func Result(err error) HealthResult {
	if err == nil {
		return HealthResult{Status: Healthy, Code: "SUBSCRIPTION-SERVING-HTTPS"}
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return HealthResult{Status: Failed, Code: failure.Code}
	}
	return HealthResult{Status: Unknown, Code: "SUBSCRIPTION-SERVING-UNKNOWN"}
}

func failed(code, problem string) error { return &Failure{Code: code, Problem: problem} }
