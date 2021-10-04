package utils

import (
	"time"

	"github.com/araddon/dateparse"
)

// GlobalLoc is global timezone for converting time format
var GlobalLoc *time.Location

// UTCNow returns now in utc timezone
func UTCNow() time.Time {
	return time.Now().UTC()
}

// SetGlobalLoc set global timezone
func SetGlobalLoc() (err error) {
	GlobalLoc, err = time.LoadLocation("UTC")
	return err
}

// GuessTimeFmtAndConvert guesses input time string and converts to output format string
func GuessTimeFmtAndConvert(timeStr, outFmt string) (string, error) {
	loc := GlobalLoc
	if loc == nil {
		var err error
		loc, err = time.LoadLocation("UTC")
		if err != nil {
			return "", err
		}
	}
	parsed, err := GuessTimeFmt(timeStr, loc)
	if err != nil {
		return "", err
	}
	return parsed.In(loc).Format(outFmt), nil
}

// GuessTimeFmt guesses input time string and converts to time object
func GuessTimeFmt(timeStr string, loc *time.Location) (time.Time, error) {
	parsed, err := dateparse.ParseIn(timeStr, loc)
	if err != nil {
		return time.Time{}, err
	}
	return parsed, nil
}

// ConvTimeFmt converts time from input format to ouput format
func ConvTimeFmt(timeStr, inFmt, outFmt string) (string, error) {
	v, err := time.Parse(inFmt, timeStr)
	if err != nil {
		return "", err
	}
	return v.Format(outFmt), nil
}
