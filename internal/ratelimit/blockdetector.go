// Package ratelimit detects a WAF/rate-limit kicking in during a scan by
// counting consecutive status codes.
package ratelimit

// Action tells the calling module what to do after an observation.
type Action int

const (
	ActionNone Action = iota
	ActionPauseAndReduce
	ActionAbort
	ActionAlertOnly
)

type Detector struct {
	Max403    int
	Max429    int
	OnTrigger string // pause_and_reduce | abort | alert_only

	consecutive403 int
	consecutive429 int
}

func NewDetector(max403, max429 int, onTrigger string) *Detector {
	return &Detector{Max403: max403, Max429: max429, OnTrigger: onTrigger}
}

// Observe takes an HTTP status code and returns the action to take. A code
// outside 403/429 resets the counters (blocking must be consecutive to
// trigger; a lone 403 amid 200s is normal).
func (d *Detector) Observe(statusCode int) Action {
	switch statusCode {
	case 403:
		d.consecutive403++
		d.consecutive429 = 0
	case 429:
		d.consecutive429++
		d.consecutive403 = 0
	default:
		d.consecutive403 = 0
		d.consecutive429 = 0
		return ActionNone
	}

	if d.consecutive403 >= d.Max403 || d.consecutive429 >= d.Max429 {
		d.consecutive403 = 0
		d.consecutive429 = 0
		switch d.OnTrigger {
		case "abort":
			return ActionAbort
		case "alert_only":
			return ActionAlertOnly
		default:
			return ActionPauseAndReduce
		}
	}
	return ActionNone
}
