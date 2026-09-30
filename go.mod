module smbproxy

go 1.27

require github.com/jfjallid/go-smb v0.12.0

require (
	github.com/jfjallid/gofork v1.7.6 // indirect
	github.com/jfjallid/gokrb5/v9 v9.1.0 // indirect
	github.com/jfjallid/golog v0.4.0 // indirect
	github.com/jfjallid/mstypes v0.0.2 // indirect
	github.com/jfjallid/ndr v0.2.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.50.0 // indirect
	software.sslmate.com/src/go-pkcs12 v0.7.0 // indirect
)

replace github.com/jfjallid/go-smb v0.12.0 => github.com/vnxme/go-smb v0.0.0-20260930100014-306d546211ab
