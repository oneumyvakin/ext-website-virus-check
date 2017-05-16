package main

import (
	"path/filepath"
	"testing"

	"os"

	"github.com/oneumyvakin/osext"
)

func TestWordpress(t *testing.T) {
	var err error
	binaryDir, err = osext.ExecutableFolder()
	if err != nil {
		t.Fatalf("Failed ExecutableFolder: %s", err)
	}
	logger = getLogger()

	webApp := wordpress{
		dbPath:      filepath.Join(binaryDir, "Wordpress"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Wordpress"),
		log:         logger,
	}

	t.Log("dbPath:", webApp.dbPath, "webRootPath:", webApp.webRootPath)

	vdb := &vulnerabilityDb{}
	err = vdb.load(webApp.getDbPath())
	if err != nil {
		t.Fatalf("Failed vdb.load(): %s", err)
	}

	webApp.setDb(vdb)

	vulns, err := webApp.check()
	if err != nil {
		t.Fatalf("Failed webApp.check(): %s", err)
	}

	if len(vulns) == 0 {
		t.Fatal("Zero vulnerabilities found", err)
	}

	items := make(map[string]bool)
	items["wp-content/plugins/google-adsense-and-hotel-booking/google_adsense_and_hotel_booking.php"] = false
	items["wp-content/themes/atahualpa/functions.php"] = false
	items["wp-content/plugins/aviary-image-editor-add-on-for-gravity-forms/aviary-for-gravity-forms.php"] = false
	for _, v := range vulns {
		if v.Error.IsError {
			t.Errorf("Vulnerability '%s' has error: %#v", v.Title, v.Error)
		}
		if _, found := items[v.Path]; found {
			t.Logf("Found plugin version: %s", v.SoftwareVersion)
			items[v.Path] = true
		}
	}

	for path, found := range items {
		if !found {
			t.Errorf("Test vulnerability %s not found", path)
		}
	}
}
