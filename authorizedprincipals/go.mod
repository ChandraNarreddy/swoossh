module github.com/ChandraNarreddy/swoossh/authorizedprincipals

go 1.16

require github.com/aws/aws-sdk-go v1.40.45

require (
	github.com/ChandraNarreddy/swoossh/group v0.0.0-00010101000000-000000000000
	github.com/ChandraNarreddy/swoossh/sshcert v0.0.0-00010101000000-000000000000
)

replace github.com/ChandraNarreddy/swoossh/sshcert => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/sshcert

replace github.com/ChandraNarreddy/swoossh/group => /Users/chandrakanthreddy/Documents/ssh/ssh_hostside/PrincipalsCommand/group
