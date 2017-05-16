package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-ini/ini"
	"github.com/hashicorp/go-version"
)

var drupal7DetectFile = filepath.Join("modules", "system", "system.info")

type drupal7 struct {
	webRootPath string
	dbPath      string
	db          *vulnerabilityDb
	found       []Vulnerability
	log         *log.Logger
}

type drupal7module struct {
	Name    string `ini:"name"`
	Version string `ini:"version"`
}

func (d7 drupal7) getDbPath() string {
	return d7.dbPath
}

func (d7 *drupal7) setDb(db *vulnerabilityDb) {
	d7.db = db
}

func (d7 *drupal7) getDbVersion() int {
	return d7.db.dbRegistry.DbVersion
}

func (d7Module *drupal7module) normalizeVersion() {
	splited := strings.Split(d7Module.Version, "-")
	splitedLen := len(splited)
	if splitedLen == 1 {
		d7Module.Version = splited[0] // Form: 3.19
	}
	if splitedLen == 2 {
		d7Module.Version = splited[1] // Form: 7.x-3.19
	}
	if splitedLen > 2 {
		d7Module.Version = splited[1] // Form: 7.x-2.16+0-dev
	}
}

func (d7 drupal7) check() ([]Vulnerability, error) {
	var wg sync.WaitGroup
	wg.Add(len(d7.db.Vulnerabilities))

	for _, v := range d7.db.Vulnerabilities {
		go d7.checkVulnerability(&wg, v)
	}

	wg.Wait()

	return d7.found, nil
}

func (d7 *drupal7) checkVulnerability(wg *sync.WaitGroup, v Vulnerability) {
	defer wg.Done()

	pluginPath := filepath.Join(d7.webRootPath, v.Path)
	if _, err := os.Stat(pluginPath); err != nil && err != os.ErrNotExist {
		return
	}
	d7Module := drupal7module{}
	err := ini.MapTo(&d7Module, pluginPath)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginIniDecode"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error(), "path": pluginPath}
		d7.found = append(d7.found, v)
		return
	}

	d7.log.Printf("Found module '%s' version '%s' at %s", d7Module.Name, d7Module.Version, pluginPath)
	d7Module.normalizeVersion()

	moduleVersion, err := version.NewVersion(d7Module.Version)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionInvalid"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d7.found = append(d7.found, v)
		return
	}
	vulnVersionFrom, err := version.NewVersion(v.VersionFrom)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d7.found = append(d7.found, v)
		return
	}
	vulnVersionTo, err := version.NewVersion(v.VersionTo)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d7.found = append(d7.found, v)
		return
	}
	if (moduleVersion.GreaterThan(vulnVersionFrom) || moduleVersion.Equal(vulnVersionFrom)) && (moduleVersion.LessThan(vulnVersionTo) || moduleVersion.Equal(vulnVersionTo)) {
		v.SoftwareVersion = d7Module.Version
		d7.found = append(d7.found, v)
	}
}
