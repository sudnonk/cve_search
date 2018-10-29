package main

import (
	"fmt"
	"io"
	"log"
	"os/exec"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

func main() {
	out, err := exec.Command("sqlite3", CpeDbPath, "'select cpe_uri from categorized_cpes'").Output()
	if err != nil {
		log.Fatal(err)
	}

	cmd := exec.Command("peco")
	stdin, _ := cmd.StdinPipe()
	io.WriteString(stdin, string(out))
	stdin.Close()

	out2, err2 := cmd.Output()
	if err2 != nil {
		log.Fatal(err2)
	}

	fmt.Println(out2)
}
