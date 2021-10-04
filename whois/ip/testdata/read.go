package testdata

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
)

var testdatafolder string

func init() {
	_, currFile, _, _ := runtime.Caller(0)
	testdatafolder = filepath.Dir(currFile)
}

// ReadRawtext return content of test file
func ReadRawtext(fpath string) ([]byte, error) {
	absFpath := filepath.Join(testdatafolder, fpath)
	return ioutil.ReadFile(absFpath)
}
