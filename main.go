package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
)

const (
	CpeDbPath  = "/root/vuln_scan/cpe.sqlite3"
	CveDbPath  = "/root/vuln_scan/cve.sqlite3"
	OvalDbPath = "/root/vuln_scan/oval.sqlite3"
)

type CVE struct {
	CveID             string
	Cvss2BaseScore    string
	Cvss2Severity     string
	Cvss3BaseScore    string
	Cvss3BaseSeverity string
}

type Pack struct {
	Name    string
	Version string
	Release string
	Arch    string
}

func main() {
	var (
		v     = flag.Int("redhat", 7, "RedHat 5 or 6 or 7")
		fname = flag.String("filename", "", "Path to list of packages")
	)
	flag.Parse()
	file, err := os.Open(*fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	packs := parseFile(file)
	findCvdIDs(packs, *v)

}

func parseFile(file *os.File) []Pack {
	var packs []Pack
	s := bufio.NewScanner(file)
	for s.Scan() {
		l := s.Text()
		pack, err := parsePackage(l)
		if err != nil {
			log.Println(err)
		}

		packs = append(packs, pack)
	}
	if s.Err() != nil {
		log.Fatal(s.Err())
	}

	return packs
}

//openssl-1.0.1e-30.el6_6.11.x86_64 -> openssl 1.0.1e 30.el6_6 11 x86_64
func parsePackage(p string) (Pack, error) {
	r := regexp.MustCompile(`(.+)-(\d+.*)-(\d+.*)\.(x86_64|noarch|i386)`)
	re := r.FindStringSubmatch(p)
	if len(re) > 0 {
		fmt.Println(re[1])
	} else {
		return Pack{}, errors.New("Failed to parse package: " + p)
	}

	return Pack{
		re[1],
		re[2],
		re[3],
		re[4],
	}, nil
}

func findCvdIDs(packs []Pack, v int) []string {
	for _, pack := range packs {
		cmd := exec.Command("goval-dictionary", "select", "-dbpath", OvalDbPath, "-by-package", "redhat", string(v), pack.Name)
		var out bytes.Buffer
		var stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(out.String(), stderr.String())
	}

	var strs []string
	return strs
}
