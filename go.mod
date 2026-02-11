module github.com/fyroc/encryptroom

go 1.24.5

require golang.org/x/crypto v0.0.0

require golang.org/x/sys v0.0.0 // indirect

replace golang.org/x/crypto => ./third_party/golang.org/x/crypto

replace golang.org/x/sys => ./third_party/golang.org/x/sys
