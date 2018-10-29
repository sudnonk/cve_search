package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

func main() {
	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("sqlite3", CpeDbPath, "'select cpe_uri from categorized_cpes'")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Fatal(1, fmt.Sprint(err)+stderr.String())
		return
	}
	/*
		cmd = exec.Command("peco")
		stdin, _ := cmd.StdinPipe()
		io.WriteString(stdin, string(out))
		stdin.Close()

		out2, err2 := cmd.Output()
		if err2 != nil {
			log.Fatal(2, out2, err2)
		}

		fmt.Println(out2)
	*/
}
