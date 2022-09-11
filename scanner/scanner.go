package scanner

type Checker interface {
	Check() *Result
}

type Result struct {
	Vulnerable bool
	Success    bool
	Reason     string
}
