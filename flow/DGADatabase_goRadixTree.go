package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime/debug"
	"sync"
	"time"

	"github.com/hashicorp/go-memdb"
)

type DGARow struct {
	DomainName    string
	MalwareFamily string
}

// add a % of data read
// Add workers

const targetDir = "./2019-01-07-dgarchive_full"

var counter int

var DGADatabase *memdb.MemDB
var tableName string
var startTime time.Time

func initDGADatabase() {
	debug.SetGCPercent(-1)
	tableName = "DGA_Table"
	schema := getDGASchema(tableName)

	fmt.Println("Creating in-memory db...")
	var err error
	DGADatabase, err = memdb.NewMemDB(schema)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Reading data from: ", targetDir)
	files, err := ioutil.ReadDir(targetDir)
	if err != nil {
		log.Fatal(err)
	}

	// Create a channel to buffer files to be inserted into db
	filesChannel := make(chan os.FileInfo, 100)
	// Create a waitgroup to wait for the database to be completely created
	var wgDB sync.WaitGroup

	// Goroutine to add files to the channel
	go func() {
		for _, file := range files {
			fmt.Println("Added file: ", file.Name())
			filesChannel <- file
		}

		// After all files have been added, close the channel
		// to indicate no further files are to be added
		close(filesChannel)
	}()

	// Create workers to pull files to begin parsing into the db
	var totalWorkers int = 1
	counter = 0
	for i := 0; i < totalWorkers; i++ {
		wgDB.Add(1)
		fmt.Println("Create dbworker, ", i)
		startTime = time.Now()
		dataBaseWorker(filesChannel, &wgDB)
	}

	// Wait till all workers have completed parsing
	wgDB.Wait()
}

func dataBaseWorker(channel <-chan os.FileInfo, wg *sync.WaitGroup) {
	defer wg.Done()
	for file := range channel {
		rowsCommitted := 0
		start := time.Now()
		// fmt.Println("Parsing file: ", file.Name(), "| time start: ", start)
		// regex for .csv files
		matched, _ := regexp.MatchString(".csv", file.Name())
		if !matched {
			continue
		}

		fmt.Println("Opening ", file.Name(), "...")

		// Open csv files and assign a reader
		filePath := targetDir + "/" + file.Name()
		csvFile, _ := os.Open(filePath)
		reader := csv.NewReader(csvFile)

		// Ready a write transaction for db
		writeTransaction := DGADatabase.Txn(true)

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
			counter++
			if counter > 100000 {
				fmt.Println("heartbeat...", time.Now().Sub(startTime))
				counter = 0
			}
			if err != nil {
				log.Fatal(err)
			}
			rowsCommitted++
		}

		// Commit the transaction for this file
		startCommit := time.Now()
		writeTransaction.Commit()
		end := time.Now()
		fmt.Println("**", end.Sub(startTime), "** Commitment made for file: ", file.Name())
		fmt.Println("Total TimeLapsed: ", end.Sub(start), "| Rows committed: ", rowsCommitted)
		fmt.Println("Commit time: ", end.Sub(startCommit))
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
