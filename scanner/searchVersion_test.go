package main

import (
	"strings"
	"testing"
)

func TestSearchVersion(t *testing.T) {
	samples := map[string]string{
		"Version 0.5":                           "0.5",
		"version 1.2.3":                         "1.2.3",
		"@version 1.4.1":                        "1.4.1",
		"# Version 0.3 / genuine.":              "0.3",
		"@version 0.8.0 2011-03-11":             "0.8.0",
		"public $Version = '5.2.16';":           "5.2.16",
		"define('SIMPLEPIE_VERSION', '1.3.1');": "1.3.1",
		"Version: 3.0 (Beta r7)":                "3.0-beta.7",
	}
	for raw, result := range samples {
		v, err := searchVersion(strings.NewReader(raw))
		if err != nil {
			t.Fatalf(`Failed to searchVersion("%s"): %s`, raw, err)
		}
		if result != v {
			t.Fatalf(`Failed to searchVersion("%s"): "%s" != "%s"`, raw, result, v)
		}
	}

}
