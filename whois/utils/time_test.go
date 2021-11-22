package utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuessTimeFmtAndConvert(t *testing.T) {
	out, err := GuessTimeFmtAndConvert("2021-08-03", "2006-01-02T15:04:05+00:00")
	assert.Nil(t, err)
	assert.Equal(t, "2021-08-03T00:00:00+00:00", out)

	out, err = GuessTimeFmtAndConvert("Mon Jan  2 20:48:59 2021", "2006-01-02T15:04:05+00:00")
	assert.Nil(t, err)
	assert.Equal(t, "2021-01-02T20:48:59+00:00", out)

	out, err = GuessTimeFmtAndConvert("2013-03-08T11:41:10-0800", "2006-01-02T15:04:05+00:00")
	assert.Nil(t, err)
	assert.Equal(t, "2013-03-08T19:41:10+00:00", out)

	out, err = GuessTimeFmtAndConvert("abc", "2006-01-02T15:04:05+00:00")
	assert.NotNil(t, err)
	assert.Empty(t, out)
}

func TestConvTimeFmt(t *testing.T) {
	out, err := ConvTimeFmt("2021-08-03", "2006-01-02", "2006-01-02T15:04:05+00:00")
	assert.Nil(t, err)
	assert.Equal(t, "2021-08-03T00:00:00+00:00", out)

	out, err = ConvTimeFmt("2021-08-03", "2006-01-02 15:04", "2006-01-02T15:04:05+00:00")
	assert.NotNil(t, err)
	assert.Empty(t, out)
}

func TestConvTimeFmtInLocation(t *testing.T) {
	loc, err := time.LoadLocation("Asia/Taipei")
	require.Nil(t, err)
	out, err := ConvTimeFmtInLocation("2013-03-08 11:41:10", "2006-01-02 15:04:05", "2006-01-02T15:04:05+00:00", loc)
	assert.Nil(t, err)
	assert.Equal(t, "2013-03-08T03:41:10+00:00", out)
}
