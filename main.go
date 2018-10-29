package main

import (
	"fmt"
	"github.com/mattn/go-pipeline"
	"log"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

func main() {
	out, err := pipeline.Output(
		[]string{"sqlite3", CpeDbPath, "'select cpe_uri from categorized_cpes'"},
		[]string{"peco"},
	)
	if err != nil {
		log.Fatal(out, err)
	}
	fmt.Println(string(out))
}
