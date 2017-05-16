package main

import (
	"path/filepath"
	"testing"

	"os"

	"github.com/oneumyvakin/osext"
)

func TestJoomla3(t *testing.T) {
	var err error
	binaryDir, err = osext.ExecutableFolder()
	if err != nil {
		t.Fatalf("Failed ExecutableFolder: %s", err)
	}
	logger = getLogger()

	webApp := joomla3{
		dbPath:      filepath.Join(binaryDir, "Joomla3"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Joomla3"),
		log:         logger,
	}

	t.Log("dbPath:", webApp.dbPath, "webRootPath:", webApp.webRootPath)

	vdb := &vulnerabilityDb{}
	err = vdb.load(webApp.getDbPath())
	if err != nil {
		t.Fatalf("Failed vdb.load(): %s", err)
	}

	if len(vdb.Vulnerabilities) == 0 {
		t.Fatal("Zero vulnerabilities loaded")
	}

	webApp.setDb(vdb)

	vulns, err := webApp.check()
	if err != nil {
		t.Fatalf("Failed webApp.check(): %s", err)
	}

	if len(vulns) == 0 {
		t.Fatal("Zero vulnerabilities found")
	}

	items := make(map[string]bool)
	items["High Priority - Core - Elevated Privileges (affecting Joomla! 1.6.0 through 3.6.4)"] = false
	items["High Priority - Component Huge-IT Catalog 1.0.7 - SQL Injection"] = false

	if len(vulns) != len(items) {
		t.Logf("Found vulnerabilities: %#v", vulns)
		t.Error("Vulnerabilities found != exists")
	}

	for _, v := range vulns {
		if v.Error.IsError {
			t.Errorf("Vulnerability '%s' has error: %#v", v.Title, v.Error)
		}
		if _, found := items[v.Title]; found {
			t.Logf("Found Title: %s", v.Title)
			t.Logf("Found Version: %s", v.SoftwareVersion)
			items[v.Title] = true
		}
	}

	for title, found := range items {
		if !found {
			t.Errorf("Test vulnerability not found: %s", title)
		}
	}
}
