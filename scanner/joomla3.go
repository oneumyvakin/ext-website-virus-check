package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/hashicorp/go-version"
)

var joomla3VersionFile = filepath.Join("libraries", "cms", "version", "version.php")
var joomla3DetectFile = joomla3VersionFile

type joomla3 struct {
	webRootPath string
	version     string
	dbPath      string
	db          *vulnerabilityDb
	found       []Vulnerability
	log         *log.Logger
}

type joomla3Plugin struct {
	Name    string `xml:"name"`
	Version string `xml:"version"`
	Author  string `xml:"author"`
}

func (j *joomla3) getDbPath() string {
	return j.dbPath
}

func (j *joomla3) setDb(db *vulnerabilityDb) {
	j.db = db
}

func (j *joomla3) getDbVersion() int {
	return j.db.dbRegistry.DbVersion
}

func (j *joomla3) getVersion() (err error) {

	f, err := os.Open(filepath.Join(j.webRootPath, joomla3VersionFile))
	if err != nil {
		return err
	}
	var release string  // const RELEASE = '3.5';
	var devLevel string // const DEV_LEVEL = '1';
	releaseRegExp := regexp.MustCompile(`RELEASE = '(\d\.\d)'`)
	devLevelRegExp := regexp.MustCompile(`DEV_LEVEL = '(\d)'`)
	s := bufio.NewScanner(f)
	for s.Scan() {
		if release == "" {
			match := releaseRegExp.FindAllStringSubmatch(s.Text(), -1)
			if len(match) > 0 && len(match[0]) == 2 {
				release = match[0][1]
			}
		}

		if devLevel == "" {
			match := devLevelRegExp.FindAllStringSubmatch(s.Text(), -1)
			if len(match) > 0 && len(match[0]) == 2 {
				devLevel = match[0][1]
			}
		}
	}

	if release == "" || devLevel == "" {
		return fmt.Errorf("Failed get joomla version from file %s", filepath.Join(j.webRootPath, joomla3VersionFile))
	}

	j.version = fmt.Sprintf("%s.%s", release, devLevel)
	_, err = version.NewVersion(j.version)

	return
}

func (j *joomla3) check() ([]Vulnerability, error) {
	err := j.getVersion()
	if err != nil {
		return j.found, err
	}
	var wg sync.WaitGroup
	wg.Add(len(j.db.Vulnerabilities))

	for _, v := range j.db.Vulnerabilities {
		go j.checkVulnerability(&wg, v)
	}

	wg.Wait()

	return j.found, nil
}

func (j *joomla3) checkVulnerability(wg *sync.WaitGroup, v Vulnerability) {
	defer wg.Done()

	vulnVersionFrom, err := version.NewVersion(v.VersionFrom)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		j.found = append(j.found, v)
		return
	}
	vulnVersionTo, err := version.NewVersion(v.VersionTo)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorDbItem"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		j.found = append(j.found, v)
		return
	}

	if v.SoftwareType == "Joomla Core" {
		joomlaVersion, err := version.NewVersion(j.version)
		if err != nil {
			v.Error.IsError = true
			v.Error.LocaleKey = "scannerErrorAppVersionParseError"
			v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			j.found = append(j.found, v)
			return
		}

		if (joomlaVersion.GreaterThan(vulnVersionFrom) || joomlaVersion.Equal(vulnVersionFrom)) && (joomlaVersion.LessThan(vulnVersionTo) || joomlaVersion.Equal(vulnVersionTo)) {
			v.Path = j.webRootPath
			v.SoftwareVersion = j.version
			j.found = append(j.found, v)

		}
		return
	}

	pluginPath := filepath.Join(j.webRootPath, v.Path)
	if _, err := os.Stat(pluginPath); err != nil && err != os.ErrNotExist {
		return
	}
	if v.DetectByPathExists {
		j.found = append(j.found, v)
		return
	}
	f, err := os.Open(pluginPath)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorOpenPath"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		j.found = append(j.found, v)
		return
	}
	jPlugin := joomla3Plugin{}
	if v.SearchVersion {
		jPlugin.Version, err = searchVersion(f)
		f.Close()
		if err != nil {
			v.Error.IsError = true
			v.Error.LocaleKey = "scannerErrorSearchVersion"
			v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			j.found = append(j.found, v)
			return
		}
	} else {
		err = xml.NewDecoder(f).Decode(&jPlugin)
		f.Close()
		if err != nil {
			v.Error.IsError = true
			v.Error.LocaleKey = "scannerErrorPluginXmlDecode"
			v.Error.LocaleArgs = map[string]string{"msg": err.Error(), "path": pluginPath}
			j.found = append(j.found, v)
			return
		}
		if jPlugin.Version == "" {
			j.log.Printf("Version is empty. Skip %s", v.Path)
			return
		}
		if v.SoftwareAuthor != "" && v.SoftwareAuthor != jPlugin.Author {
			j.log.Printf("Author mismatch '%s' != '%s'. Skip %s", v.SoftwareAuthor, jPlugin.Author, v.Path)
			return
		}
	}

	sanitizedVersion, err := sanitizeVersion(jPlugin.Version)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionSearh"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		j.found = append(j.found, v)
		return
	}
	pluginVersion, err := version.NewVersion(sanitizedVersion)
	if err != nil {
		v.Error.IsError = true
		v.Error.LocaleKey = "scannerErrorPluginVersionInvalid"
		v.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		j.found = append(j.found, v)
		return
	}

	if (pluginVersion.GreaterThan(vulnVersionFrom) || pluginVersion.Equal(vulnVersionFrom)) && (pluginVersion.LessThan(vulnVersionTo) || pluginVersion.Equal(vulnVersionTo)) {
		v.SoftwareVersion = sanitizedVersion
		j.found = append(j.found, v)
	}
}
