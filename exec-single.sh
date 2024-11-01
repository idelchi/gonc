go run ./cmd/gonc -d -k caafcb1dcff90a2a37054c6a30c546d0932494a1fff5a0f8a76af57aafea73b5dbe26f38ee093788a7550788cf80aa70d4b3b3ab13de39cdbde2d33435cfb49c enc test.sh
go run ./cmd/gonc -k caafcb1dcff90a2a37054c6a30c546d0932494a1fff5a0f8a76af57aafea73b5dbe26f38ee093788a7550788cf80aa70d4b3b3ab13de39cdbde2d33435cfb49c --decrypt-ext=.new dec test.sh.enc

go run ./cmd/gonc -k 4bcaa6d16799915ff8440b4e9f5773b3bc9b4621a65d8c4b374b107da2705e02 enc test.sh
