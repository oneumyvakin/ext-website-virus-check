package main

import (
	"testing"
)

func TestSanitizeVersion(t *testing.T) {
	samples := map[string]string{
		"0.1":             "0.1",
		"1.2.3":           "1.2.3",
		"1.2.3.4":         "1.2.3.4",
		"1.1 ASD":         "1.1",
		"1.2ASD":          "1.2",
		"1.3-ASD":         "1.3",
		"1.4 (Beta)":      "1.4-beta",
		"1.4-beta.1":      "1.4-beta.1",
		"1.4.1Beta":       "1.4.1-beta",
		"1.4.2-beta":      "1.4.2-beta",
		"1.4.3 (Beta2)":   "1.4.3-beta.2",
		"1.4.4.1-alpha":   "1.4.4.1-alpha",
		"1.4.4.1 Alpha 6": "1.4.4.1-alpha.6",
		"1.4.4.2-beta7":   "1.4.4.2-beta.7",
		"1.4.4.3-Beta.8":  "1.4.4.3-beta.8",
	}
	for raw, result := range samples {
		v, err := sanitizeVersion(raw)
		if err != nil {
			t.Errorf(`Failed to sanitizeVersion("%s"): %s`, raw, err)
		}
		if result != v {
			t.Errorf(`Failed to sanitizeVersion("%s"): "%s" != "%s"`, raw, result, v)
		}
	}
}
