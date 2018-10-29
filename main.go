package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"log"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

const (
	CpeDbPath = "/root/cpe.sqlite3"
	CveDbPath = "/root/cve.sqlite3"
)

func main() {
	//DBからCPE一覧を取ってくる
	db, err := sql.Open("sqlite3", CpeDbPath)
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query(
		`select cpe_uri from categorized_cpes`,
	)
	if err != nil {
		log.Fatal(err)
	}

	var cpeUri string
	var num int
	for rows.Next() {
		var uri string

		if err := rows.Scan(&uri); err != nil {
			log.Fatal(err)
			return
		}

		cpeUri += uri + "\n"
		num++
		if num%1000 == 0 {
			log.Println(num)
		}
	}
	rows.Close()

	log.Println("DB done.")

	var out bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("peco")
	stdin, _ := cmd.StdinPipe()
	io.WriteString(stdin, cpeUri)
	stdin.Close()

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	log.Println("Run peco.")
	err2 := cmd.Run()
	if err2 != nil {
		log.Fatal(2, fmt.Sprint(err2)+stderr.String())
	}

	fmt.Println(out)
}
