package main

import (
	"path/filepath"
	"testing"

	"os"

	"github.com/oneumyvakin/osext"
)

func TestDrupal8(t *testing.T) {
	var err error
	binaryDir, err = osext.ExecutableFolder()
	if err != nil {
		t.Fatalf("Failed ExecutableFolder: %s", err)
	}
	logger = getLogger()

	webApp := drupal8{
		dbPath:      filepath.Join(binaryDir, "Drupal8"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Drupal8"),
		log:         logger,
	}

	t.Log("dbPath:", webApp.dbPath, "webRootPath:", webApp.webRootPath)

	vdb := &vulnerabilityDb{}
	err = vdb.load(webApp.getDbPath())
	if err != nil {
		t.Fatalf("Failed vdb.load(): %s", err)
	}

	if len(vdb.Vulnerabilities) == 0 {
		t.Fatal("Zero vulnerabilities loaded", err)
	}

	webApp.setDb(vdb)

	vulns, err := webApp.check()
	if err != nil {
		t.Fatalf("Failed webApp.check(): %s", err)
	}

	if len(vulns) == 0 {
		t.Fatal("Zero vulnerabilities found", webApp.found)
	}

	items := make(map[string]bool)
	items["modules/auto_login_url/auto_login_url.info.yml"] = false
	itemsMustNotFound := make(map[string]bool)
	itemsMustNotFound["modules/drd_agent/drd_agent.info.yml"] = false

	for _, v := range vulns {
		if v.Error.IsError {
			t.Errorf("Vulnerability '%s' has error: %#v", v.Title, v.Error)
		}
		if _, found := items[v.Path]; found {
			t.Logf("Found plugin version: %s", v.SoftwareVersion)
			items[v.Path] = true
		}
		if _, found := itemsMustNotFound[v.Path]; found {
			t.Logf("Found plugin version: %s", v.SoftwareVersion)
			itemsMustNotFound[v.Path] = true
		}
	}

	for path, found := range items {
		if !found {
			t.Errorf("Test vulnerability %s not found", path)
		}
	}

	for path, found := range itemsMustNotFound {
		if found {
			t.Errorf("Test vulnerability %s is found, but should be not.", path)
		}
	}
}
