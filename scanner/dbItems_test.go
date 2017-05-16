package main

import (
	"path/filepath"
	"strings"
	"testing"

	"os"

	"github.com/oneumyvakin/osext"
)

func TestDbItems(t *testing.T) {
	var err error
	binaryDir, err = osext.ExecutableFolder()
	if err != nil {
		t.Fatalf("Failed ExecutableFolder: %s", err)
	}
	logger = getLogger()

	webAppWordpress := &wordpress{
		dbPath:      filepath.Join(binaryDir, "Wordpress"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Wordpress"),
		log:         logger,
	}
	webAppJoomla3 := &joomla3{
		dbPath:      filepath.Join(binaryDir, "Joomla3"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Joomla3"),
		log:         logger,
	}
	webAppDrupal7 := &drupal7{
		dbPath:      filepath.Join(binaryDir, "Drupal7"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Drupal7"),
		log:         logger,
	}
	webAppDrupal8 := &drupal8{
		dbPath:      filepath.Join(binaryDir, "Drupal8"),
		webRootPath: filepath.Join(os.Getenv("GOPATH"), "src", pleskExtensionName, "testdata", "Drupal8"),
		log:         logger,
	}

	testCases := []struct {
		name       string
		webApp     webApp
		pathChecks map[string]string
	}{
		{
			"WordpressDb",
			webAppWordpress,
			map[string]string{
				"Plugin": "wp-content/plugins/",
				"Theme":  "wp-content/themes/",
			},
		},
		{
			"Joomla3Db",
			webAppJoomla3,
			map[string]string{
				"Component": "administrator/components",
				"Module":    "modules/",
			},
		},
		{
			"Drupal7Db",
			webAppDrupal7,
			map[string]string{
				"Module": "sites/all/modules/",
			},
		},
		{
			"Drupal8Db",
			webAppDrupal8,
			map[string]string{
				"Module": "modules/",
				"Core":   "core/modules/",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vdb := &vulnerabilityDb{}
			err = vdb.load(tc.webApp.getDbPath())
			if err != nil {
				t.Fatalf("Failed vdb.load(): %s", err)
			}

			var previousTitle string
			var previousName string
			var previousVersionTo string
			var previousUrl string
			var previousPath string
			for _, item := range vdb.Vulnerabilities {
				for softwareTypeCondition, pathStart := range tc.pathChecks {
					if strings.Contains(strings.ToLower(item.SoftwareType), softwareTypeCondition) {
						if !strings.HasPrefix(item.Path, pathStart) {
							t.Errorf("No '%s' in path %s but SoftwareType = '%s' in Title: %s", pathStart, item.Path, item.SoftwareType, item.Title)
						}
					}
				}

				if !strings.Contains(item.Title, item.SoftwareName) {
					t.Errorf("No SoftwareName '%s' in item Title: %s", item.SoftwareName, item.Title)
				}
				if !item.DetectByPathExists && item.VersionTo != "0.0.0" && !strings.Contains(item.Title, item.VersionTo) {
					t.Errorf("No VersionTo '%s' in title: %s", item.VersionTo, item.Title)
				}
				if item.AdvisoryURL == previousUrl {
					t.Errorf("Copy-paste AdvisoryURL '%s' in item: %s", item.AdvisoryURL, item.Title)
				}

				if item.VersionTo != "0.0.0" && item.VersionTo == previousVersionTo {
					t.Errorf("Copy-paste VersionTo '%s' in item: %s", item.VersionTo, item.Title)

				}
				if item.SoftwareName == previousName {
					if !strings.Contains(previousTitle, item.SoftwareName) {
						t.Errorf("Copy-paste SoftwareName '%s' in item: %s", item.VersionTo, item.Title)
					}
				}
				if item.Path == previousPath {
					t.Errorf("Copy-paste Path '%s' in item: %s", item.Path, item.Title)
				}

				previousTitle = item.Title
				previousVersionTo = item.VersionTo
				previousUrl = item.AdvisoryURL
				previousName = item.SoftwareName
				previousPath = item.Path
			}
		})
	}
}
