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

// ReadRawtext returns content of test file
func ReadRawtext(fpath string) ([]byte, error) {
	absFpath := filepath.Join(testdatafolder, fpath)
	return ioutil.ReadFile(absFpath)
}

// ReadRawtexts returns all contents in given test folder
func ReadRawtexts(folderPath string) ([][]byte, error) {
	absFolderPath := filepath.Join(testdatafolder, folderPath)
	files, err := ioutil.ReadDir(absFolderPath)
	if err != nil {
		return nil, err
	}
	rawtexts := [][]byte{}
	for _, f := range files {
		absFpath := filepath.Join(absFolderPath, f.Name())
		content, err := ioutil.ReadFile(absFpath)
		if err != nil {
			return nil, err
		}
		rawtexts = append(rawtexts, content)
	}
	return rawtexts, nil
}
