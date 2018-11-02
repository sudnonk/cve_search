package main

import (
	"bufio"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
)

const (
	CpeDbPath  = "/root/vuln_scan/cpe.sqlite3"
	CveDbPath  = "/root/vuln_scan/cve.sqlite3"
	OvalDbPath = "/root/vuln_scan/oval.sqlite3"
)

type CVE struct {
	CveID             string
	Cvss2BaseScore    float32
	Cvss2Severity     string
	Cvss3BaseScore    float32
	Cvss3BaseSeverity string
}

type Pack struct {
	Name    string
	Version string
	Release string
	Arch    string
}

type Result struct {
	Pack Pack
	CVEs map[string]CVE
}

func main() {
	var (
		fname = flag.String("filename", "", "Path to list of packages")
	)
	flag.Parse()
	file, err := os.Open(*fname)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	packs := parseFile(file)

	CVEs := make(map[string]CVE)
	var results []Result
	for _, pack := range packs {
		result := Result{Pack: pack}
		for _, cveID := range findCveIDs(pack) {
			if cve, ok := CVEs[cveID]; ok {
				result.CVEs[cveID] = cve
			} else {
				CVEs[cveID] = fillCVE(cveID)
				result.CVEs[cveID] = cve
			}
		}
		results = append(results, result)
	}

	fmt.Println(results)
}

func parseFile(file *os.File) []Pack {
	var packs []Pack
	s := bufio.NewScanner(file)
	for s.Scan() {
		l := s.Text()
		pack, err := parsePackage(l)
		if err != nil {
			log.Println(err)
			continue
		}

		packs = append(packs, pack)
	}
	if s.Err() != nil {
		log.Fatal(s.Err())
	}

	return packs
}

var r = regexp.MustCompile(`(.+)-(\d+.*)-(\d+.*)\.(x86_64|noarch|i386)`)

//openssl-1.0.1e-30.el6_6.11.x86_64 -> openssl 1.0.1e 30.el6_6 11 x86_64
func parsePackage(p string) (Pack, error) {
	re := r.FindStringSubmatch(p)
	if len(re) != 5 {
		return Pack{}, errors.New("Failed to parse package: " + p)
	}

	return Pack{
		re[1],
		re[2],
		re[3],
		re[4],
	}, nil
}

func findCveIDs(pack Pack) []string {
	db, err := sql.Open("sqlite3", OvalDbPath)
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query(
		`select definition_id,version,not_fixed_yet from packages where name = '?' and version like '%?'`,
		pack.Name, pack.Version+"-"+pack.Release,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var DefinitionID int
		var version string
		var notFixedYet bool

		if err := rows.Scan(&DefinitionID, &version, &notFixedYet); err != nil {
			log.Println(err, pack.Name, pack.Version+"-"+pack.Release)
		}

		rows2, err := db.Query(
			`select cve_id from cves where advisory_id = (select id from advisories where definition_id = ?)`,
			DefinitionID,
		)
		if err != nil {
			log.Println(err, pack.Name)
		}

		for rows2.Next() {
			var cveID string
			if err := rows2.Scan(&cveID); err != nil {
				log.Println(err, pack.Name)
			} else {
				cveIDs = append(cveIDs, cveID)
			}
		}

		if err := rows2.Err(); err != nil {
			log.Fatal(err)
		}

		rows2.Close()
	}

	return cveIDs
}

func fillCVE(cveID string) CVE {
	db, err := sql.Open("sqlite3", CveDbPath)
	if err != nil {
		log.Fatal(err)
	}

	nvdRow := db.QueryRow(
		`select id from nvd_jsons where cveid = ?`,
		cveID,
	)
	var nvdJsonId int
	if err := nvdRow.Scan(&nvdJsonId); err != nil {
		log.Println(err, cveID)
	}

	cvss3 := db.QueryRow(
		`select base_score,base_severity from cvss3 where nvd_json_id = ?`,
		nvdJsonId,
	)
	var Cvss3BaseScore float32
	var Cvss3BaseSeverity string
	if err := cvss3.Scan(&Cvss3BaseScore, &Cvss3BaseSeverity); err != nil {
		log.Println(err, cveID)
	}

	cvss2 := db.QueryRow(
		`select base_score,severity from cvss2 where nvd_json_id = ?`,
		nvdJsonId,
	)
	var Cvss2BaseScore float32
	var Cvss2Severity string
	if err := cvss2.Scan(&Cvss2BaseScore, &Cvss2Severity); err != nil {
		log.Println(err, cveID)
	}

	return CVE{
		CveID:             cveID,
		Cvss2BaseScore:    Cvss2BaseScore,
		Cvss2Severity:     Cvss2Severity,
		Cvss3BaseScore:    Cvss3BaseScore,
		Cvss3BaseSeverity: Cvss3BaseSeverity,
	}
}
