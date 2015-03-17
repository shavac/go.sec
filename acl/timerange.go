package acl

import (
	"github.com/shavac/go.sec/acl/adapter"
	"time"
	"strings"
	"errors"
	"fmt"
)

const (
	timeRange = "TIMERANGE"
	timeFormat = "20060102150405"
)

func init() {
	EntryRegistry[timeRange] = NewTimeRangeEntry
}

type TimeRangeEntry struct {
	adapter.EntryRecord
	start, end time.Time
}

func NewTimeRangeEntry(secureId int, operation, target string, permit bool, tRange string, runOnce bool) (Entry, error) {
	p := strings.Split(tRange, "-")
	if len(p) != 2 {
		return nil, fmt.Errorf("Error when parse time range string:%s", tRange)
	}
	s, e := p[0], p[1]
	start, err := time.Parse(timeFormat, s)
	if err!= nil {
		return nil, err
	}
	end, err := time.Parse(timeFormat, e)
	if err!= nil {
		return nil, err
	}
	return &TimeRangeEntry{
		adapter.EntryRecord{
			RecordKey: adapter.RecordKey {
				SecureId:  secureId,
				Operation: operation,
			},
			Type:      timeRange,
			Target:    target,
			Permit:    permit,
			Ctx:       tRange,
			RunOnce:   runOnce,
		},
		start, end,
	}, nil
}

func (e *TimeRangeEntry) SecureId() int {
	return e.EntryRecord.SecureId
}

func (e *TimeRangeEntry) Type() string {
	return base
}

func (e *TimeRangeEntry) Match(target string, d interface{}) (bool, error) {
	if t, ok := d.(time.Time); ! ok {
		return false, errors.New("Must be time.Time type")
	} else {
		return target == e.EntryRecord.Target && e.start.Before(t) && e.end.After(t), nil
	}
}

func (e *TimeRangeEntry) Decide() bool {
	return e.EntryRecord.Permit
}

func (e *TimeRangeEntry) RunOnce() bool {
	return e.EntryRecord.RunOnce
}

func (e *TimeRangeEntry) Key() adapter.RecordKey {
	return e.RecordKey
}

func (e *TimeRangeEntry) Record() adapter.EntryRecord {
	return e.EntryRecord
}


