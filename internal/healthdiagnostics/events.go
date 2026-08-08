package healthdiagnostics

import (
	"context"
	"errors"
	"sort"
	"time"
)

const (
	EventRetentionPeriod = 30 * 24 * time.Hour
	EventRetentionBytes  = 50 << 20

	CheckOperation OperationID = "Check"

	InfoSeverity    EventSeverity = "Info"
	WarningSeverity EventSeverity = "Warning"
	ErrorSeverity   EventSeverity = "Error"
)

// EventRecord is the complete allowlist for one retained diagnostic event.
type EventRecord struct {
	Time        time.Time       `json:"time"`
	Module      Module          `json:"module"`
	OperationID OperationID     `json:"operation_id"`
	ChangeSetID ChangeSetID     `json:"change_set_id,omitempty"`
	Severity    EventSeverity   `json:"severity"`
	Code        FindingCode     `json:"code"`
	Explanation string          `json:"explanation"`
	Outcome     MutationOutcome `json:"outcome,omitempty"`
}

func (event DiagnosticEvent) Record() EventRecord {
	return EventRecord{
		Time: event.time, Module: event.module, OperationID: event.operation, ChangeSetID: event.changeSet,
		Severity: event.severity, Code: event.code, Explanation: event.explanation, Outcome: event.outcome,
	}
}

// RestoreDiagnosticEvent validates persisted allowlisted facts. Unknown fields
// are rejected by the storage Adapter before this boundary.
func RestoreDiagnosticEvent(record EventRecord) (DiagnosticEvent, error) {
	event := DiagnosticEvent{
		time: record.Time, module: record.Module, operation: record.OperationID, changeSet: record.ChangeSetID,
		severity: record.Severity, code: record.Code, explanation: record.Explanation, outcome: record.Outcome,
	}
	if !validDiagnosticEvent(event) {
		return DiagnosticEvent{}, errors.New("diagnostic event is invalid")
	}
	return event, nil
}

func (result CheckResult) DiagnosticEvents() []DiagnosticEvent {
	return append([]DiagnosticEvent(nil), result.events...)
}

func checkEvent(result ModuleResult) DiagnosticEvent {
	return DiagnosticEvent{
		time: result.CheckedAt, module: result.Module, operation: CheckOperation,
		severity: severity(result.Status), code: result.Code, explanation: result.Explanation,
	}
}

func severity(status HealthStatus) EventSeverity {
	switch status {
	case Healthy:
		return InfoSeverity
	case NeedsAttention:
		return WarningSeverity
	default:
		return ErrorSeverity
	}
}

func validDiagnosticEvent(event DiagnosticEvent) bool {
	if event.time.IsZero() || event.time.Location() != time.UTC || !knownModule(event.module) {
		return false
	}
	if event.operation != CheckOperation || event.changeSet != "" || event.outcome != "" {
		return false
	}
	for _, status := range []HealthStatus{Healthy, NeedsAttention, Failed, Unknown} {
		if event.code == NamedCheckCode(event.module, status) && event.severity == severity(status) && event.explanation == explanation(event.module, status) {
			return true
		}
	}
	return event.code == "HEALTH-DIAGNOSTICS-CHECK-UNKNOWN" && event.severity == ErrorSeverity && event.explanation == explanation(event.module, Unknown)
}

type EventStorage interface {
	Load() ([]DiagnosticEvent, error)
	Replace([]DiagnosticEvent) error
	EncodedSize([]DiagnosticEvent) (int64, error)
}

type EventHistory struct {
	storage EventStorage
	now     func() time.Time
}

func NewEventHistory(storage EventStorage, now func() time.Time) EventHistory {
	if now == nil {
		now = time.Now
	}
	return EventHistory{storage: storage, now: now}
}

// ScheduledCheck delegates classification to Check, then retains only the
// opaque safe events created by that same call.
func (module Interface) ScheduledCheck(ctx context.Context, history EventHistory, installation InstallationSummary, inspections ...NamedInspection) (CheckResult, error) {
	result := module.Check(ctx, installation, inspections...)
	return result, history.RecordCheck(result)
}

func (history EventHistory) RecordCheck(result CheckResult) error {
	return history.record(result.DiagnosticEvents())
}

func (history EventHistory) record(additions []DiagnosticEvent) error {
	if history.storage == nil {
		return errors.New("diagnostic event storage is unavailable")
	}
	events, err := history.storage.Load()
	if err != nil {
		return errors.New("diagnostic event history is unavailable")
	}
	events = append(events, additions...)
	_, err = history.retain(events)
	return err
}

func (history EventHistory) Events() ([]DiagnosticEvent, error) {
	if history.storage == nil {
		return nil, errors.New("diagnostic event storage is unavailable")
	}
	events, err := history.storage.Load()
	if err != nil {
		return nil, errors.New("diagnostic event history is unavailable")
	}
	return history.retain(events)
}

func (history EventHistory) retain(events []DiagnosticEvent) ([]DiagnosticEvent, error) {
	now := history.now().UTC()
	for _, event := range events {
		if !validDiagnosticEvent(event) || event.time.After(now) {
			return nil, errors.New("diagnostic event history is invalid")
		}
	}
	sort.SliceStable(events, func(left, right int) bool {
		first, second := events[left], events[right]
		if !first.time.Equal(second.time) {
			return first.time.Before(second.time)
		}
		if first.module != second.module {
			return first.module < second.module
		}
		return first.code < second.code
	})
	cutoff := now.Add(-EventRetentionPeriod)
	first := 0
	for first < len(events) && events[first].time.Before(cutoff) {
		first++
	}
	events = append([]DiagnosticEvent(nil), events[first:]...)
	for {
		size, err := history.storage.EncodedSize(events)
		if err != nil || size < 0 {
			return nil, errors.New("diagnostic event size is unavailable")
		}
		if size <= EventRetentionBytes {
			break
		}
		if len(events) == 0 {
			return nil, errors.New("diagnostic event storage cannot meet its size limit")
		}
		events = events[1:]
	}
	if err := history.storage.Replace(events); err != nil {
		return nil, errors.New("diagnostic event history replacement failed")
	}
	return append([]DiagnosticEvent(nil), events...), nil
}
