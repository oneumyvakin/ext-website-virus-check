package main

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-yaml/yaml"
	"github.com/hashicorp/go-version"
)

var drupal8DetectFile = filepath.Join("core", "modules", "system", "system.info.yml")

type drupal8 struct {
	webRootPath string
	dbPath      string
	db          *vulnerabilityDb
	found       []Vulnerability
	log         *log.Logger
}

type drupal8module struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
}

func (d8 drupal8) getDbPath() string {
	return d8.dbPath
}

func (d8 *drupal8) setDb(db *vulnerabilityDb) {
	d8.db = db
}

func (d8 *drupal8) getDbVersion() int {
	return d8.db.dbRegistry.DbVersion
}

func (d8Module *drupal8module) normalizeVersion() {
	splited := strings.Split(d8Module.Version, "-")
	splitedLen := len(splited)
	if splitedLen == 1 {
		d8Module.Version = splited[0] // Form: 1.3
	}
	if splitedLen == 2 {
		d8Module.Version = splited[1] // Form: 8.x-1.3
	}
	if splitedLen > 2 {
		d8Module.Version = splited[1] // Form: 8.x-1.3+0-dev
	}
}

func (d8 drupal8) check() ([]Vulnerability, error) {
	var wg sync.WaitGroup
	wg.Add(len(d8.db.Vulnerabilities))

	for _, v := range d8.db.Vulnerabilities {
		go d8.checkVulnerability(&wg, v)
	}
	wg.Wait()
	return d8.found, nil
}

func (d8 *drupal8) checkVulnerability(wg *sync.WaitGroup, v Vulnerability) {
	defer wg.Done()

	modulePath := filepath.Join(d8.webRootPath, v.Path)
	if _, err := os.Stat(modulePath); err != nil && err != os.ErrNotExist {
		return
	}

	b, err := ioutil.ReadFile(modulePath)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorOpenPath"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d8.found = append(d8.found, v)
		return
	}

	d8Module := drupal8module{}
	err = yaml.Unmarshal(b, &d8Module)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginYmlDecode"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error(), "path": modulePath}
		d8.found = append(d8.found, v)
		return
	}

	rawVersion := d8Module.Version
	d8Module.normalizeVersion()
	d8.log.Printf("Found module '%s' raw version '%s', normalized version '%s' at %s", d8Module.Name, rawVersion, d8Module.Version, modulePath)

	moduleVersion, err := version.NewVersion(d8Module.Version)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionInvalid"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d8.found = append(d8.found, v)
		return
	}
	vulnVersionFrom, err := version.NewVersion(v.VersionFrom)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d8.found = append(d8.found, v)
		return
	}
	vulnVersionTo, err := version.NewVersion(v.VersionTo)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		d8.found = append(d8.found, v)
		return
	}
	if (moduleVersion.GreaterThan(vulnVersionFrom) || moduleVersion.Equal(vulnVersionFrom)) && (moduleVersion.LessThan(vulnVersionTo) || moduleVersion.Equal(vulnVersionTo)) {
		v.SoftwareVersion = d8Module.Version
		d8.found = append(d8.found, v)
		d8.log.Printf("Found vulnerability '%s' in module '%s' normalized version '%s' at %s", v.Title, d8Module.Name, d8Module.Version, modulePath)
	}
}
