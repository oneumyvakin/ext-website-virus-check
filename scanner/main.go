package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/oneumyvakin/osext"
)

const (
	pleskExtensionName = "website-virus-check"
	defaultLogPrefix   = "[extension/website-virus-check]"
	storagePath        = "https://github.com/oneumyvakin/antivirus/raw/master/"
)

var (
	logger    *log.Logger
	binaryDir string
	dbs       map[string]*vulnerabilityDb
)

type webApp interface {
	check() ([]Vulnerability, error)
	getDbPath() string
	setDb(*vulnerabilityDb)
	getDbVersion() int
}

type pleskDomainId string

type pleskDomain struct {
	Error           programError
	DomainId        pleskDomainId `json:"id"`
	WebRootPath     string        `json:"documentRoot"`
	DbVersion       int
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type programReport struct {
	Error          programError
	Domains        map[pleskDomainId]pleskDomain
	ReportFilePath string
	log            *log.Logger
}

type programError struct {
	IsError    bool
	LocaleKey  string
	LocaleArgs map[string]string
}

func (e programError) Error() string {
	eBytes, err := json.Marshal(e)
	if err != nil {
		return `{"IsError": false, "LocaleKey": "", "LocaleArgs":{} }`
	}
	return string(eBytes)
}

func main() {
	report := programReport{
		Domains: make(map[pleskDomainId]pleskDomain),
	}

	var err error
	binaryDir, err = osext.ExecutableFolder()
	if err != nil {
		report.Error.IsError = true
		report.Error.LocaleKey = "scannerErrorFailedGetBinaryFolder"
		report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		report.reportJson()
		return
	}
	report.ReportFilePath = filepath.Join(binaryDir, "report.json")
	logger = getLogger()
	report.log = logger
	report.log.Println(os.Args)

	getReport := flag.Bool("report", false, "Retrive current report")
	scanDomains := flag.String("scan-domains", "", "Path to JSON file of domains")
	dbRootPath := flag.String("db-root-path", binaryDir, "Path to vulnerabilities DB files")
	flag.Parse()

	if *getReport {
		if _, err := os.Stat(report.ReportFilePath); err != nil && os.IsNotExist(err) {
			report.reportJson()
			return
		}

		reportFile, err := os.Open(report.ReportFilePath)
		if err != nil {
			report.Error.IsError = true
			report.Error.LocaleKey = "scannerErrorOpenReportFile"
			report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			report.reportJson()
			return
		}

		err = json.NewDecoder(reportFile).Decode(&report)
		if err != nil {
			report.Error.IsError = true
			report.Error.LocaleKey = "scannerErrorFailedDecodeReportJson"
			report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			report.reportJson()
			return
		}

		report.reportJson()
		return
	}
	if *scanDomains == "" {
		report.Error.IsError = true
		report.Error.LocaleKey = "scannerErrorEmptyDomainsJson"
		report.Error.LocaleArgs = map[string]string{}
		report.reportJson()
		return
	}

	scanDomainsFile, err := os.Open(*scanDomains)
	if err != nil {
		report.Error.IsError = true
		report.Error.LocaleKey = "scannerErrorOpenDomainsJson"
		report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		report.reportJson()
		return
	}

	err = json.NewDecoder(scanDomainsFile).Decode(&report.Domains)
	if err != nil {
		report.Error.IsError = true
		report.Error.LocaleKey = "scannerErrorDecodeDomainsJson"
		report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		report.reportJson()
		return
	}

	var wg sync.WaitGroup
	dbs = make(map[string]*vulnerabilityDb)
	for id, domain := range report.Domains {
		webApp, err := newWebApp(domain.WebRootPath)
		if err != nil {
			domain.Error.IsError = false
			domain.Error.LocaleKey = "scannerInfoNoWebApp"
			domain.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			report.Domains[id] = domain
			continue
		}

		dbs[webApp.getDbPath()] = &vulnerabilityDb{dbRootPath: *dbRootPath}
		err = dbs[webApp.getDbPath()].load(webApp.getDbPath())
		if err != nil {
			report.Error.IsError = true
			report.Error.LocaleKey = "scannerErrorFailedDbLoad"
			report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
			report.reportJson()
			return
		}

		webApp.setDb(dbs[webApp.getDbPath()])

		go report.check(id, webApp, &wg)
		wg.Add(1)
	}

	wg.Wait()
	report.reportJson()
}

func (report programReport) check(id pleskDomainId, app webApp, wg *sync.WaitGroup) {
	defer wg.Done()

	domain := report.Domains[id]
	domain.DbVersion = app.getDbVersion()
	vulns, err := app.check()
	if err != nil {
		domain.Error.IsError = true
		domain.Error.LocaleKey = "scannerErrorFailedWebAppCheck"
		domain.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		report.Domains[id] = domain
		return
	}

	domain.Vulnerabilities = vulns
	report.Domains[id] = domain
}

func newWebApp(webRootPath string) (webApp, error) {
	detectFiles := map[string]string{
		"Joomla3":   joomla3DetectFile,
		"Drupal7":   drupal7DetectFile,
		"Drupal8":   drupal8DetectFile,
		"Wordpress": wordpress4DetectFile,
	}

	appLog := getLogger()
	appLog.SetPrefix(fmt.Sprintf("%s %s ", defaultLogPrefix, webRootPath))
	for id, detectFile := range detectFiles {
		if _, err := os.Stat(filepath.Join(webRootPath, detectFile)); err != nil && err != os.ErrNotExist {
			continue
		}

		appLog.SetPrefix(fmt.Sprintf("%s %s:%s ", defaultLogPrefix, id, webRootPath))
		if id == "Joomla3" {
			return &joomla3{
				dbPath:      id,
				webRootPath: webRootPath,
				log:         appLog,
			}, nil
		}
		if id == "Drupal7" {
			return &drupal7{
				dbPath:      id,
				webRootPath: webRootPath,
				log:         appLog,
			}, nil
		}
		if id == "Drupal8" {
			return &drupal8{
				dbPath:      id,
				webRootPath: webRootPath,
				log:         appLog,
			}, nil
		}
		if id == "Wordpress" {
			return &wordpress{
				dbPath:      id,
				webRootPath: webRootPath,
				log:         appLog,
			}, nil
		}
	}

	err := errors.New("Web Application not found")
	appLog.Println(err)
	return nil, err
}

func (report programReport) reportJson() {
	if report.log == nil {
		report.log = log.New(os.Stdout, "Default ", log.Lshortfile|log.LUTC)
	}

	jsonOutput, err := json.Marshal(report)
	if err != nil {
		jsonOutput, _ := json.Marshal(err)
		report.log.Println(string(jsonOutput))
		println(string(jsonOutput))
		os.Exit(1)
		return
	}
	err = ioutil.WriteFile(report.ReportFilePath, jsonOutput, os.ModeExclusive)
	if err != nil {
		report.Error.IsError = true
		report.Error.LocaleKey = "scannerErrorWriteReportFile"
		report.Error.LocaleArgs = map[string]string{"msg": err.Error()}
		os.Exit(1)
	}

	report.log.Println(string(jsonOutput))
	fmt.Fprint(os.Stdout, string(jsonOutput))

	if report.Error.IsError {
		os.Exit(1)
	}

	return
}

func getLogger() *log.Logger {
	pleskLogPath := getPleskPanelLog()
	logFilePath := path.Join(binaryDir, "virustotal_scanner.log")

	logFile, err := os.OpenFile(pleskLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
	if err != nil {
		logFile, err = os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		if err != nil {
			log.Fatal("Failed to open log file", pleskLogPath, err)
		}
	}

	return log.New(logFile, defaultLogPrefix+" ", log.LstdFlags|log.Lshortfile|log.LUTC)
}

func searchVersion(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(strings.ToLower(line), "version") {
			continue
		}

		return sanitizeVersion(line)
	}

	return "", errors.New("failed search version")
}

func sanitizeVersion(raw string) (string, error) {
	alphaBetaRelease := regexp.MustCompile(`(?i)(alpha|beta)(?:.+)?(\d+)`)
	alphaBeta := regexp.MustCompile(`(?i)(alpha|beta)`)
	regExpLong := regexp.MustCompile(`\d\.\d+\.\d+\.\d+`)
	regExpFull := regexp.MustCompile(`\d\.\d+\.\d+`)
	regExpShort := regexp.MustCompile(`\d\.\d+`)

	draft := regExpLong.FindAllString(raw, 1)
	if len(draft) > 0 {
		result := draft[0]
		abr := alphaBetaRelease.FindAllStringSubmatch(raw, 1)
		if len(abr) > 0 && len(abr[0]) > 2 {
			result = fmt.Sprintf("%s-%s.%s", draft[0], abr[0][1], abr[0][2])
		} else {
			ab := alphaBeta.FindAllString(raw, 1)
			if len(ab) > 0 {
				result = fmt.Sprintf("%s-%s", draft[0], ab[0])
			}
		}

		err := probeVersion(result)
		if err == nil {
			return strings.ToLower(result), nil
		}
	}

	draft = regExpFull.FindAllString(raw, 1)
	if len(draft) > 0 {
		result := draft[0]
		abr := alphaBetaRelease.FindAllStringSubmatch(raw, 1)
		if len(abr) > 0 && len(abr[0]) > 2 {
			result = fmt.Sprintf("%s-%s.%s", draft[0], abr[0][1], abr[0][2])
		} else {
			ab := alphaBeta.FindAllString(raw, 1)
			if len(ab) > 0 {
				result = fmt.Sprintf("%s-%s", draft[0], ab[0])
			}
		}

		err := probeVersion(result)
		if err == nil {
			return strings.ToLower(result), nil
		}
	}

	draft = regExpShort.FindAllString(raw, 1)
	if len(draft) > 0 {
		result := draft[0]
		abr := alphaBetaRelease.FindAllStringSubmatch(raw, 1)
		if len(abr) > 0 && len(abr[0]) > 2 {
			result = fmt.Sprintf("%s-%s.%s", draft[0], abr[0][1], abr[0][2])
		} else {
			ab := alphaBeta.FindAllString(raw, 1)
			if len(ab) > 0 {
				result = fmt.Sprintf("%s-%s", draft[0], ab[0])
			}
		}

		err := probeVersion(result)
		if err == nil {
			return strings.ToLower(result), nil
		}
	}

	return "", errors.New("failed sanitize version")
}

func probeVersion(ver string) (err error) {
	_, err = version.NewVersion(ver)
	return
}

func download(url, dstPath string) (err error) {
	r, err := httpGet(url)
	if err != nil {
		err = fmt.Errorf("Failed to download %s: failed to get file: %s", url, err)
		logger.Println(err.Error())
		return
	}

	f, err := os.Create(dstPath)
	if err != nil {
		err = fmt.Errorf("Failed to download %s: failed to get file: %s", url, err)
		logger.Println(err.Error())
		return
	}
	defer ioClose(f)

	n, err := io.Copy(f, r)
	if err != nil {
		err = fmt.Errorf("Failed to download %s: failed to write file %s: %s", url, filepath.Join(binaryDir, dstPath), err)
		logger.Println(err.Error())
		return
	}

	logger.Printf("Download %d bytes from %s to %s", n, url, filepath.Join(binaryDir, dstPath))
	return
}

func httpGet(url string) (io.Reader, error) {
	logger.Printf("Get content from %s", url)

	var err error
	var r *http.Response
	var content bytes.Buffer
	for i := 0; i <= 5; i++ {
		r, err = http.Get(url)
		if err == nil {
			if r.StatusCode == 404 {
				err = fmt.Errorf("HTTP ERROR %d : %s", r.StatusCode, url)
				return nil, err
			}
			_, err = content.ReadFrom(r.Body)
			if err == nil {
				break
			} else {
				logger.Printf("Failed to get body from %s: %s at try %d", url, err, i)
			}
		} else {
			logger.Printf("Failed to get content from %s: %s at try %d", url, err, i)
		}
		time.Sleep(5 * time.Second)
	}
	if r != nil {
		defer ioClose(r.Body)
	}
	if err != nil {
		err = fmt.Errorf("Failed to get content from %s: %s", url, err)
		logger.Println(err.Error())
		return nil, err
	}

	logger.Printf("Done content from %s", url)
	return &content, nil
}

func ioClose(c io.Closer) {
	err := c.Close()
	if err != nil {
		logger.Printf("Failed to close resource: %s", err)
	}
}

func getPleskPanelLog() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("plesk_dir"), "admin", "logs", "php_error.log")
	} else {
		return "/usr/local/psa/admin/logs/panel.log"
	}
}
