# Pengo

A tool (or collection of tools), to do _some_ pentesting in Go super easily.

I wanted to create a collection of tools inspired by the black hat go book (heavily recommended read).

## Design

Design of this project is a collection of _somewhat_ standalone tools, that then are used with the Go plugin system to create a single binary that can be used to do pentesting.

## Usage

Copy the example yaml config file to `~/.pengo.yaml` and edit it to your needs.

Enable the plugins you want to use in the config file, for example;

```yaml
plugins:
  - portscanner
  - databasescanner
```

```bash
make
```

## Tools

### Port Scanner

A port scanner. Simple.

Config:

```yaml
portscanner:
  target: scanme.nmap.org
  portrange: 1-1024
```

Shows open ports on the target

### Database Scanner

A database scanner, scans for column names matching your input.

Config:

```yaml
databasescanner:
  dbtype: mysql
  mysql:
    uri: root:my-secret-pw@tcp(127.0.0.1:64399)/
  search:
    - password
    - secret
    - token
    - key
```