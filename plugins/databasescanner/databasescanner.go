// taken and modified from black hat go
package main

import (
	"fmt"
	"regexp"

	"github.com/spf13/viper"
	"github.com/trelore/pengo/scanner"
)

type DBScanner struct{}

func Checker() scanner.Checker {
	return &DBScanner{}
}

func (d *DBScanner) Check() *scanner.Result {
	var miner DBSchemer
	switch viper.GetViper().GetString("databasescanner.dbtype") {
	case "mysql":
		miner = &MySQLMiner{
			uri: viper.GetViper().GetString("databasescanner.mysql.uri"),
		}
	default:
		return &scanner.Result{
			Vulnerable: false,
			Success:    false,
			Reason:     "no database type specified",
		}
	}
	columns, err := Search(miner)
	if err != nil {
		return &scanner.Result{
			Vulnerable: false,
			Success:    false,
			Reason:     fmt.Errorf("error searching database: %v", err).Error(),
		}
	}
	reason := fmt.Sprintf("found columns: %v", columns)
	return &scanner.Result{
		Vulnerable: len(columns) > 0,
		Success:    true,
		Reason:     reason,
	}
}

type DBSchemer interface {
	Schema() (*Schema, error)
}

type Schema struct {
	columns []string // in format of "database.table.column"
}

func Search(m DBSchemer) ([]string, error) {
	schema, err := m.Schema()
	if err != nil {
		return nil, fmt.Errorf("error getting schema: %v", err)
	}
	ret := []string{}
	re := getRegex()
	// for loops go brrrrrrrrrrrrrrrrrrrrrrrrr
	for _, column := range schema.columns {
		for _, r := range re {
			if r.MatchString(column) {
				ret = append(ret, column)
			}
		}
	}
	return ret, nil
}

func getRegex() []*regexp.Regexp {
	ret := []*regexp.Regexp{}
	for _, s := range viper.GetViper().GetStringSlice("databasescanner.search") {
		ret = append(ret, regexp.MustCompile(fmt.Sprintf(".*%s.*", s)))
	}
	return ret
}
