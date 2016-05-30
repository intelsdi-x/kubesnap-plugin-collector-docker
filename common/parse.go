package common

import (
	"io/ioutil"
	"strings"
)

import "strconv"

func ReadUintFromFile(path string, bits int) (uint64, error) {
	if valb, err := ioutil.ReadFile(path); err != nil {
		return 0, err
	} else {
		var val uint64
		val, err = strconv.ParseUint(strings.TrimSpace(string(valb)), 10, bits)
		return val, err
	}
}
