package main

import (
	"github.com/mattn/go-pipeline"
	"log"
	"os/exec"
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

	cmd := exec.Command("go-cve-dictionary", "server")
	cmd.Start()
	log.Println(cmd.Process.Pid)

	out2, err2 := exec.Command("curl", "-v -H \"Accept: application/json\" -H \"Content-type: application/json\" -X POST -d '{\"name\": \""+cpeUri+"\"}' http://localhost:1323/cpes").Output()
	log.Println(cmd.Process.Pid)
	defer cmd.Process.Kill()

	if err != nil {
		log.Fatal(out2, err2)
	}

	log.Println(out2)
}
