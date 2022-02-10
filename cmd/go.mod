module github.com/ChandraNarreddy/swoossh/cmd

go 1.16

replace github.com/ChandraNarreddy/swoossh/authorizedprincipals => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/authorizedprincipals

replace github.com/ChandraNarreddy/swoossh/group => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/group

replace github.com/ChandraNarreddy/swoossh/sshcert => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/sshcert

replace github.com/ChandraNarreddy/swoossh/httpserver => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/httpserver

replace github.com/ChandraNarreddy/swoossh/ca => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/ca

replace github.com/ChandraNarreddy/swoossh/storage => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/storage

replace github.com/ChandraNarreddy/swoossh/user => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/user

require (
	github.com/ChandraNarreddy/swoossh/authorizedprincipals v0.0.0-00010101000000-000000000000
	github.com/ChandraNarreddy/swoossh/group v0.0.0-00010101000000-000000000000
	github.com/ChandraNarreddy/swoossh/sshcert v0.0.0-00010101000000-000000000000
	github.com/aws/aws-sdk-go v1.41.19 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/sys v0.0.0-20211002104244-808efd93c36d // indirect
)
