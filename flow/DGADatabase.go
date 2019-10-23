package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"

	"github.com/hashicorp/go-memdb"
)

type DGARow struct {
	DomainName    string
	MalwareFamily string
}

const targetDir = "./test_data"

var DGA_db *memdb.MemDB

func initDGADatabase() {
	var tableName string = "DGA_Table"
	schema := getDGASchema(tableName)

	fmt.Println("Creating in-memory db...")
	var err error
	DGA_db, err = memdb.NewMemDB(schema)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Reading data from: ", targetDir)
	files, err := ioutil.ReadDir(targetDir)
	if err != nil {
		log.Fatal(err)
	}

	// Cycle through files in directory extracting data and inserting in the db
	for _, file := range files {
		// regex for .csv files
		matched, _ := regexp.MatchString(".csv", file.Name())
		if !matched {
			continue
		}

		// Open csv files and assign a reader
		filePath := targetDir + "/" + file.Name()
		csvFile, _ := os.Open(filePath)
		reader := csv.NewReader(csvFile)

		// Ready a write transaction for db
		writeTransaction := DGA_db.Txn(true)

		// fmt.Println("Reading from: ", filePath) -> can make logs later
		for {
			row, err := reader.Read()
			if err == io.EOF {
				break
			}

			// parse information from the correct csv rows (hardcoded implementation)
			domainNameData, malwareFamilyData := extractCorrectDataRows(row)

			// insert into the db via the writeTransaction already open

			err = writeTransaction.Insert(tableName, DGARow{domainNameData, malwareFamilyData})
			if err != nil {
				log.Fatal(err)
			}
		}

		// Commit the transaction for this file
		writeTransaction.Commit()
	}

}

// Return the DBschema of the DGA lookup
func getDGASchema(tableName string) *memdb.DBSchema {

	// Note: memdb demands that at least one 'id' column exists, hence, the
	// domainName will act as the id
	schema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			tableName: &memdb.TableSchema{
				Name: tableName,
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:    "id",
						Unique:  true,
						Indexer: &memdb.StringFieldIndex{Field: "DomainName"},
					},
					"malwareFamily": &memdb.IndexSchema{
						Name:    "malwareFamily",
						Unique:  false,
						Indexer: &memdb.StringFieldIndex{Field: "MalwareFamily"},
					},
				},
			},
		},
	}

	return schema
}

/*
Given a list of values from the csv file
Extract correct column values -> return the domain name and the malware family
*/
func extractCorrectDataRows(rows []string) (string, string) {
	// Number of columns in given row
	length := len(rows)

	/*
		At this point in time, there are said formats for the DGA domain name csvfiles
			i.) 3 rows: domain name, id, malware family
			ii.) 5 rows: domain name, id, timestamp, timestamp, malware family
	*/

	if length == 3 {
		return rows[0], rows[2]
	} else if length == 5 {
		return rows[0], rows[4]
	} else {
		// bad error handling
		return "very", "bad"
	}
}
