package main

import (
	"bufio"
	"errors"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/hashicorp/go-version"
)

var wordpress4VersionFile = filepath.Join("wp-includes", "version.php")
var wordpress4DetectFile = wordpress4VersionFile

type wordpress struct {
	webRootPath string
	version     string
	dbPath      string
	db          *vulnerabilityDb
	found       []Vulnerability
	log         *log.Logger
}

type wordpressPlugin struct {
	Version string
}

func (wp *wordpress) getDbPath() string {
	return wp.dbPath
}

func (wp *wordpress) setDb(db *vulnerabilityDb) {
	wp.db = db
}

func (wp *wordpress) getDbVersion() int {
	return wp.db.dbRegistry.DbVersion
}

func (wp *wordpress) getVersion() (err error) {
	f, err := os.Open(filepath.Join(wp.webRootPath, wordpress4VersionFile))
	if err != nil {
		return err
	}

	verRegExp := regexp.MustCompile(`\$wp_version = '(\d\.\d\.\d)'`) // $wp_version = '4.7.3';

	s := bufio.NewScanner(f)
	for s.Scan() {
		match := verRegExp.FindAllStringSubmatch(s.Text(), -1)
		if len(match) > 0 && len(match[0]) == 2 {
			wp.version = match[0][1]
			break
		}

	}

	if wp.version == "" {
		return errors.New("failed wordpress get version")
	}

	_, err = version.NewVersion(wp.version)
	if err != nil {
		return err
	}

	return
}

func (wp *wordpress) check() (found []Vulnerability, err error) {
	err = wp.getVersion()
	if err != nil {
		return
	}
	var wg sync.WaitGroup
	wg.Add(len(wp.db.Vulnerabilities))

	for _, v := range wp.db.Vulnerabilities {
		go wp.checkVulnerability(&wg, v)
	}

	wg.Wait()
	return wp.found, nil
}

func (wp *wordpress) checkVulnerability(wg *sync.WaitGroup, v Vulnerability) {
	defer wg.Done()

	vulnVersionFrom, err := version.NewVersion(v.VersionFrom)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}
	vulnVersionTo, err := version.NewVersion(v.VersionTo)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}

	if v.Path == "" {
		wpVersion, err := version.NewVersion(wp.version)
		if err != nil {
			v.Error.IsError = true
			v.Error.LocaleKey = "scannerErrorAppVersionParseError"
			v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			wp.found = append(wp.found, v)
			return
		}

		if (wpVersion.GreaterThan(vulnVersionFrom) || wpVersion.Equal(vulnVersionFrom)) && (wpVersion.LessThan(vulnVersionTo) || wpVersion.Equal(vulnVersionTo)) {
			wp.found = append(wp.found, v)
		}
		return
	}

	pluginPath := filepath.Join(wp.webRootPath, v.Path)
	if _, err := os.Stat(pluginPath); err != nil && os.IsNotExist(err) {
		return
	}
	if v.DetectByPathExists {
		wp.found = append(wp.found, v)
		return
	}
	f, err := os.Open(pluginPath)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorOpenPath"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}
	wpPlugin := wordpressPlugin{}
	wpPlugin.Version, err = searchVersion(f)
	f.Close()
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorSearchVersion"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}

	sanitizedVersion, err := sanitizeVersion(wpPlugin.Version)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionSearh"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}
	pluginVersion, err := version.NewVersion(sanitizedVersion)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionParseError"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		wp.found = append(wp.found, v)
		return
	}

	if (pluginVersion.GreaterThan(vulnVersionFrom) || pluginVersion.Equal(vulnVersionFrom)) && (pluginVersion.LessThan(vulnVersionTo) || pluginVersion.Equal(vulnVersionTo)) {
		v.SoftwareVersion = sanitizedVersion
		wp.found = append(wp.found, v)
	}
}
