module github.com/ChandraNarreddy/swoossh/storage

go 1.16

require (
	github.com/ChandraNarreddy/swoossh/ca v0.0.0-00010101000000-000000000000 // indirect
	github.com/ChandraNarreddy/swoossh/group v0.0.0-00010101000000-000000000000
	github.com/ChandraNarreddy/swoossh/sshcert v0.0.0-00010101000000-000000000000 // indirect
	github.com/ChandraNarreddy/swoossh/user v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go v1.41.19
	github.com/google/uuid v1.3.0
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519
)

replace github.com/ChandraNarreddy/swoossh/user => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/user

replace github.com/ChandraNarreddy/swoossh/group => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/group

replace github.com/ChandraNarreddy/swoossh/ca => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/ca

replace github.com/ChandraNarreddy/swoossh/sshcert => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/sshcert
