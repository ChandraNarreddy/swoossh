# **swoossh - SSH Certs with CA and Identity Management all in one**

`swoossh` simplfies SSH access and identity management. To begin -

* Deploy swoossh server
* Add users wired to their oAuth email addresses in swoossh server console
* Compile swoossh command and deploy to your posix fleet
* Modify sshd config ```/etc/ssh/sshd_config``` of fleet to trust CA key using ```TrustedUserCAKeys``` directive and to invoke the compiled swoossh command using [AuthorizedPrincipalsCommand](https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand) directive as below -
```
TrustedUserCAKeys /path_to_CA_public_key
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /path_to_compiled_swoossh_cmd -cert %k -type %t -en_key env_var_name_for_entitlement
```

What you get in return -

* Certificate based user SSH authentication
* Posix user accounts wired to their oAuth identities
* Auto provisioning of users as they login to your fleet
* Creation of any missing posix groups (if required) on the host
* Users authorized only if their group membership matches to the host's ownership criteria
* UID of user created is the same as what is set in swoossh profile
* GID of group created is the same as what is set for the group in swoossh
* Password of the user on the host is reset to the latest value upon login
* Configurable certificate validity period, defaults to 5 days in implementation provided


## Salient Features

- SSH Certificate Authority with pluggable support for CA signer implementations
  - AWS key-storage backed signer implementation provided
- SSH Certificates with the following custom extensions
  - User's POSIX ID
  - User's Primary Group
  - User's Secondary Groups
  - User's latest password
  - User's SUDO rules
- SSH POSIX client command with following abilities -
  - Matches user to any existing POSIX account by matching name and UID
  - Creates user locally if logging in for first time
  - When creating a user, can authorize user by comparing host's environment
    (env vars, ec2 tags) and user groups presented in the certificate
  - Adds locally any missing groups for the user presented in the certificate
  - Optionally can treat missing principal ID in certificate to be root user
  - Reset the matched user's password with the value passed in the certificate
  - Can be extended to appending SUDO rules by plugging in an implementation
- Pluggable storage ability for users and groups
- Provides storage implementation for AWS dynamodb based store (Schema in details)
- User identities can be fetched from oAuth compliant IdP
- Has built in support for Google Identities
- Web UI Console for server access
- Admin and non-admin roles for web based access
- Admin role can be derived by nominating a field and specific value(s) in JWT claims
- Rest APIs for administration and user interfaces to the CA server
- Admin APIs can be called using API Key based authentication too
