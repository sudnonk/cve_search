package main

import (
	"errors"
	"github.com/mattn/go-pipeline"
	"log"
	"os/exec"
	"strings"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

type CVE struct {
	CveID             string
	Cvss2BaseScore    string
	Cvss2Severity     string
	Cvss3BaseScore    string
	Cvss3BaseSeverity string
}

func main() {
	cpeUri, err := getCpeUri()
	if err != nil {
		log.Fatal(err)
	}

	cveData, err2 := getCveData(cpeUri)
	if err2 != nil {
		log.Fatal(err2)
	}

	log.Println(cveData)
}

func getCpeUri() (string, error) {
	out, err := pipeline.Output(
		[]string{"sqlite3", CpeDbPath, "SELECT cpe_uri FROM categorized_cpes"},
		[]string{"peco"},
	)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func getCveData(cpeUri string) ([]CVE, error) {
	cmd := exec.Command("go-cve-dictionary", "server", "-dbpath", CveDbPath, "&")
	cmd.Start()
	body := "{\"name\": \"" + strings.TrimRight(cpeUri, "\n") + "\"}"
	out, err := pipeline.Output(
		[]string{
			"curl",
			"-v",
			"-H",
			"Accept: application/json",
			"-H",
			"Content-type: application/json",
			"-X",
			"POST",
			"-d",
			body,
			"http://localhost:1323/cpes",
		},
		[]string{
			"jq",
			".[] | .NvdJSON | .CveID,.Cvss2.BaseScore,.Cvss2.Severity,.Cvss3.BaseScore,.Cvss3.BaseSeverity",
		},
	)
	defer cmd.Process.Kill()

	if err != nil {
		return nil, err
	}

	var lines []string
	lines = strings.Split(string(out), "\n")

	if len(lines)%5 != 0 {
		return nil, errors.New("invalid number of lines")
	}

	var cves []CVE
	for i := 0; i < len(lines); i += 5 {
		cve := CVE{
			lines[i],
			lines[i+1],
			lines[i+2],
			lines[i+3],
			lines[i+4],
		}
		cves = append(cves, cve)
	}

	return cves, nil
}
