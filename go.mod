module github.com/fyroc/encryptroom

go 1.24.5

require (
	golang.org/x/crypto v0.33.0
	golang.org/x/term v0.29.0
)

require (
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
)

replace golang.org/x/crypto => ./third_party/golang.org/x/crypto

replace golang.org/x/net => ./third_party/golang.org/x/net

replace golang.org/x/sys => ./third_party/golang.org/x/sys

replace golang.org/x/term => ./third_party/golang.org/x/term

replace golang.org/x/text => ./third_party/golang.org/x/text
