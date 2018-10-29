package main

import (
	"github.com/mattn/go-pipeline"
	"log"
	"os/exec"
	"strings"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

func main() {
	out, err := pipeline.Output(
		[]string{"sqlite3", CpeDbPath, "SELECT cpe_uri FROM categorized_cpes"},
		[]string{"peco"},
	)
	if err != nil {
		log.Fatal(out, err)
	}

	cpeUri := string(out)

	cmd := exec.Command("go-cve-dictionary", "server", "-dbpath", CveDbPath, "&")
	cmd.Start()
	log.Println(cmd.Process.Pid)
	log.Println(cpeUri)

	out2, err2 := pipeline.Output(
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
			"{'name': '" + strings.TrimRight(cpeUri, "\n") + "}'",
			"http://localhost:1323/cpes",
		},
	)
	log.Println(cmd.Process.Pid)
	defer cmd.Process.Kill()

	if err2 != nil {
		log.Fatal(out2, err2)
	}

	log.Println(string(out2))
}
