package main

import (
	"bytes"
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
	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("sqlite3", CpeDbPath, "-echo", "'select cpe_uri from categorized_cpes'")
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Fatal(1, fmt.Sprint(err)+out.String()+stderr.String())
		return
	}

	cmd = exec.Command("peco")
	stdin, _ := cmd.StdinPipe()
	io.WriteString(stdin, out.String())
	stdin.Close()

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err2 := cmd.Run()
	if err2 != nil {
		log.Fatal(2, fmt.Sprint(err2)+stderr.String())
	}

	fmt.Println(out)
}
