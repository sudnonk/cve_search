package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"log"
	"math"
	"os"
	"regexp"

	_ "github.com/mattn/go-sqlite3"
)

const (
	CveDbPath  = "/root/vuln_scan/cve.sqlite3"
	OvalDbPath = "/root/vuln_scan/oval.sqlite3"
)

type CVE struct {
	CveID             string  `json:"cve_id"`
	Cvss2BaseScore    float32 `json:"cvss_2_base_score"`
	Cvss2Severity     string  `json:"cvss_2_severity"`
	Cvss3BaseScore    float32 `json:"cvss_3_base_score"`
	Cvss3BaseSeverity string  `json:"cvss_3_base_severity"`
}

type Pack struct {
	Name    string `json:"pack_name"`
	Version string `json:"pack_version"`
	Release string `json:"pack_release"`
	Arch    string `json:"pack_arch"`
}

type Result struct {
	Pack Pack           `json:"packages"`
	CVEs map[string]CVE `json:"cves"`
}

var (
	OvalDB *sql.DB
	CveDB  *sql.DB
)
var debug debugT

type debugT bool

func (d debugT) Println(msg ...interface{}) {
	if d {
		log.Println(msg...)
	}
}
func (d debugT) Fatal(err error) {
	if d {
		log.Fatal(err)
	}
}

func main() {
	app := cli.NewApp()

	app.Name = "Search CVEs from packages"
	app.Usage = "This app finds CVEs from list of packages, then echo CVEs as JSON."
	app.Version = "1.0.0"
	cli.VersionFlag = cli.BoolFlag{
		Name:  "version, v",
		Usage: "Echo version",
	}

	app.Action = func(ctx *cli.Context) error {
		fname := ctx.String("filename")
		verbose := ctx.Bool("verbose")
		severity := ctx.StringSlice("severity")

		debug = debugT(verbose)

		packs := parseFile(fname)
		results := findCVEs(packs)
		outputJson(results, severity)

		return nil
	}

	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "verbose, V",
			Usage: "If set, echo debug logs.",
		},
		cli.StringFlag{
			Name:  "filename, f",
			Usage: "Find from the list in `PATH`",
		},
		cli.StringSliceFlag{
			Name:  "severity, s",
			Usage: "Severity that you want to find. NONE(0.0) | LOW(0.1-3.9) | MEDIUM(4.0-6.9) | HIGH(7.0-8.9) | CRITICAL(9.0-)",
		},
	}

	app.Run(os.Args)
}

//Parse file designated by `fname`, and return list of Packs.
func parseFile(fname string) []Pack {
	file, err := os.Open(fname)
	if err != nil {
		debug.Fatal(err)
	}
	defer file.Close()

	var packs []Pack
	s := bufio.NewScanner(file)
	for s.Scan() {
		l := s.Text()
		pack, err := parsePackage(l)
		if err != nil {
			debug.Println(err)
			continue
		}

		packs = append(packs, pack)
	}
	if s.Err() != nil {
		debug.Fatal(s.Err())
	}

	return packs
}

var r = regexp.MustCompile(`(.+)-(\d+.*)-(\d+.*)\.(x86_64|noarch|i386)`)

//Parse line, and convert it to Pack like below.
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

//Find CVEs the packages are affected, and return it as Result.
func findCVEs(packs []Pack) []Result {
	debug.Println("Connecting DB.")

	var err error
	OvalDB, err = sql.Open("sqlite3", OvalDbPath)
	if err != nil {
		debug.Fatal(err)
	}
	CveDB, err = sql.Open("sqlite3", CveDbPath)
	if err != nil {
		debug.Fatal(err)
	}

	debug.Println("Find CVEs start.")
	CVEs := make(map[string]CVE)
	var results []Result
	for _, pack := range packs {
		result := Result{Pack: pack, CVEs: map[string]CVE{}}
		debug.Println("Finding CveIDs for " + pack.Name)
		for _, cveID := range findCveIDs(pack) {
			debug.Println("Finding CVEs for " + cveID)
			if cve, ok := CVEs[cveID]; ok {
				result.CVEs[cveID] = cve
			} else {
				CVEs[cveID] = fillCVE(cveID)
				result.CVEs[cveID] = cve
			}
		}
		results = append(results, result)
	}
	debug.Println("Find CVEs end.")

	return results
}

//Find and return CveID the package is affected.
func findCveIDs(pack Pack) []string {
	rows, err := OvalDB.Query(
		`select definition_id,version,not_fixed_yet from packages where name = ? and version like ?`,
		pack.Name, "%"+pack.Version+"-"+pack.Release,
	)
	if err != nil {
		debug.Println(err, pack.Name, pack.Version+"-"+pack.Release)
	}
	defer rows.Close()

	var cveIDs []string
	for rows.Next() {
		var DefinitionID int
		var version string
		var notFixedYet bool

		if err := rows.Scan(&DefinitionID, &version, &notFixedYet); err != nil {
			debug.Println(err, pack.Name, pack.Version+"-"+pack.Release)
		}

		rows2, err := OvalDB.Query(
			`select cve_id from cves where advisory_id = (select id from advisories where definition_id = ?)`,
			DefinitionID,
		)
		if err != nil {
			debug.Println(err, pack.Name, DefinitionID)
		}

		for rows2.Next() {
			var cveID string
			if err := rows2.Scan(&cveID); err != nil {
				debug.Println(err, pack.Name)
			} else {
				cveIDs = append(cveIDs, cveID)
			}
		}

		if err := rows2.Err(); err != nil {
			debug.Fatal(err)
		}

		rows2.Close()
	}
	if err := rows.Err(); err != nil {
		debug.Fatal(err)
	}

	return cveIDs

}

//Find CVE of the designated CveID, and return it as CVE.
func fillCVE(cveID string) CVE {
	nvdRow := CveDB.QueryRow(
		`select id from nvd_jsons where cve_id = ?`,
		cveID,
	)
	var nvdJsonId int
	if err := nvdRow.Scan(&nvdJsonId); err != nil {
		debug.Println(err, cveID, "json")
	}

	cvss3 := CveDB.QueryRow(
		`select base_score,base_severity from cvss3 where nvd_json_id = ?`,
		nvdJsonId,
	)
	var Cvss3BaseScore float32
	var Cvss3BaseSeverity string
	if err := cvss3.Scan(&Cvss3BaseScore, &Cvss3BaseSeverity); err != nil {
		debug.Println(err, nvdJsonId, "CVSS3")
		Cvss3BaseScore = 0
		Cvss3BaseSeverity = ""
	}

	cvss2 := CveDB.QueryRow(
		`select base_score,severity from cvss2_extras where nvd_json_id = ?`,
		nvdJsonId,
	)
	var Cvss2BaseScore float32
	var Cvss2Severity string
	if err := cvss2.Scan(&Cvss2BaseScore, &Cvss2Severity); err != nil {
		debug.Println(err, nvdJsonId, "CVSS2")
		Cvss2BaseScore = 0
		Cvss2Severity = ""
	}

	return CVE{
		CveID:             cveID,
		Cvss2BaseScore:    Cvss2BaseScore,
		Cvss2Severity:     Cvss2Severity,
		Cvss3BaseScore:    Cvss3BaseScore,
		Cvss3BaseSeverity: Cvss3BaseSeverity,
	}
}

//Echo Results as JSON.
func outputJson(results []Result, severity []string) {
	var outputResults []Result
	for _, result := range results {
		r := Result{Pack: result.Pack, CVEs: map[string]CVE{}}
		if len(severity) != 0 {
			for _, cve := range result.CVEs {
				ss := math.Max(float64(cve.Cvss2BaseScore), float64(cve.Cvss3BaseScore))
				var s string
				if ss == 0.0 {
					s = "NONE"
				} else if 0.1 <= ss && ss <= 3.9 {
					s = "LOW"
				} else if 4.0 <= ss && ss <= 6.9 {
					s = "MEDIUM"
				} else if 7.0 <= ss && ss <= 8.9 {
					s = "HIGH"
				} else if 9.0 <= ss {
					s = "CRITICAL"
				}

				for _, sss := range severity {
					if sss == s {
						r.CVEs[cve.CveID] = cve
						break
					}
				}
			}
		} else {
			r.CVEs = result.CVEs
		}

		if len(r.CVEs) == 0 {
			continue
		} else {
			outputResults = append(outputResults, r)
		}
	}
	oJson, err := json.Marshal(&outputResults)
	if err != nil {
		debug.Fatal(err)
	}
	fmt.Println(string(oJson))
}
