package main

import (
	"fmt"
	"github.com/mattn/go-pipeline"
	"log"
	"os/exec"
	"strings"
	"time"
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

	errNum := 0
	cmd := exec.Command("go-cve-dictionary", "server", "-dbpath", CveDbPath, "&")
	cmd.Start()
	fmt.Println("Starting go-cve-dictionary server...")
	time.Sleep(5 * time.Second)

AGAIN:
	cveJson, err2 := getCveData(cpeUri)
	if err2 != nil {
		errNum++
		//エラーが5回起きたらrecoverやめる
		if errNum >= 5 {
			log.Fatal(err2)
		} else {
			time.Sleep(3 * time.Second)
			goto AGAIN
		}
	}
	cmd.Process.Kill()

	cves, err3 := parseJson2CVE(cveJson)
	if err3 != nil {
		log.Fatal(err3)
	}

	for cve := range cves {
		if cve.Cvss2Severity == "HIGH" || cve.Cvss2Severity == "CRITICAL" {
			fmt.Println("CveID: " + cve.CveID + " Severity: " + cve.Cvss2Severity)
		}
	}

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

func getCveData(cpeUri string) (string, error) {

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

	if err != nil {
		return "", err
	}

	return string(out), nil
}

func parseJson2CVE(json string) ([]CVE, error) {
	var lines []string
	lines = strings.Split(json, "\n")

	var cves []CVE
	for i := 0; i < len(lines)-5; i += 5 {
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
