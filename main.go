package main

import (
	"database/sql"
	"fmt"
	"log"

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

	defer rows.Close()
	var cpeUri string
	for rows.Next() {
		var uri string

		if err := rows.Scan(&uri); err != nil {
			log.Fatal(err)
			return
		}

		cpeUri += uri + "\n"
	}

	fmt.Println(cpeUri)

	/*

		var out bytes.Buffer
		var stderr bytes.Buffer

		cmd := exec.Command("sqlite3 ", CpeDbPath, " 'select cpe_uri from categorized_cpes'")
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			log.Fatal(1, fmt.Sprint(err)+stderr.String())
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
	*/
}
