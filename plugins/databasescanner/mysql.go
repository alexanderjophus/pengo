// taken and modified from black hat go
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

type MySQLMiner struct {
	uri string
}

func (m *MySQLMiner) Schema() (*Schema, error) {
	// connect to DB
	db, err := sql.Open("mysql", m.uri)
	if err != nil {
		return nil, fmt.Errorf("error opening database: %v", err)
	}
	defer db.Close()

	query := `SELECT table_schema, table_name, column_name
FROM information_schema.columns
WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
ORDER BY table_schema, table_name;`
	schemaRows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("error querying database: %v", err)
	}
	defer schemaRows.Close()

	schema := &Schema{}
	for schemaRows.Next() {
		var dbName, tableName, columnName string
		err = schemaRows.Scan(&dbName, &tableName, &columnName)
		if err != nil {
			return nil, fmt.Errorf("error scanning database: %v", err)
		}
		schema.columns = append(schema.columns, fmt.Sprintf("%s.%s.%s", dbName, tableName, columnName))
	}
	if err := schemaRows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over database: %v", err)
	}
	return schema, nil
}
