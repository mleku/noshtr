module mleku.net/noshtr

go 1.22.3

require (
	github.com/dsnet/try v0.0.3
	github.com/flynn/noise v1.1.0
	github.com/minio/sha256-simd v1.0.1
	github.com/templexxx/xorsimd v0.4.2
	github.com/zeebo/errs v1.3.0
	gitlab.com/yawning/nyquist.git v0.0.0-20231219030055-0e440ce81b06
	golang.org/x/sync v0.7.0
	lukechampine.com/frand v1.4.2
	mleku.net/ec v1.0.10
	mleku.net/slog v1.0.18
)

require (
	github.com/aead/chacha20 v0.0.0-20180709150244-8b13a72661da // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gookit/color v1.5.4 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/oasisprotocol/curve25519-voi v0.0.0-20230904125328-1f23a7beb09a // indirect
	github.com/oasisprotocol/deoxysii v0.0.0-20220228165953-2091330c22b7 // indirect
	github.com/templexxx/cpu v0.1.0 // indirect
	github.com/xo/terminfo v0.0.0-20220910002029-abceb7e1c41e // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	gitlab.com/yawning/x448.git v0.0.0-20221003101044-617eb9b7d9b7 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	mleku.net/atomic v1.11.10 // indirect
)

replace crypto/rand => github.com/minio/sha256-simd v1.0.1
