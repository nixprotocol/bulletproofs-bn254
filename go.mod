module github.com/nixprotocol/bulletproofs-bn254

go 1.23.0

require (
	github.com/consensys/gnark-crypto v0.19.2
	github.com/nixprotocol/elgamal-bn254 v0.0.0
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/bits-and-blooms/bitset v1.20.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/nixprotocol/elgamal-bn254 => ../elgamal-bn254
