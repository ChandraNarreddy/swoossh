![swoossh](https://github.com/ChandraNarreddy/swoossh/blob/f8994ea820fd81926b6a30b6999d1b0ce4b285e6/logo_2.png)
# **SwooSSH - SSH Certs with CA and Identity Management all in one (No Agents)**

SwooSSH simplfies SSH access and identity management. To begin -

* Deploy swoossh server
* Add user identities wired to their OpenIDC email addresses from swoossh server console
* Compile swoossh command and deploy to your posix fleet
* Modify sshd config ```/etc/ssh/sshd_config``` of fleet to trust CA key using ```TrustedUserCAKeys``` directive and to invoke the compiled swoossh command using [AuthorizedPrincipalsCommand](https://man.openbsd.org/sshd_config#AuthorizedPrincipalsCommand) directive as below -
```
TrustedUserCAKeys /path_to_CA_public_key
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsCommand /path_to_compiled_swoossh_cmd -targetUser %u -cert %k -type %t -en_key env_var_name_for_entitlement
```

What you get in return -

* Agent-less certificate based SSH authentication
* Posix user accounts wired to their OpenIDC identities
* Auto provisioning of users as they login to your fleet hosts
* Creation of any missing posix groups on the host
* Users authorized only if their group membership matches to the host's ownership criteria
* UID of user created is the same as what is set in user's swoossh profile
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
- User identities can be fetched from OpenID compliant IdP
- Has built in support for Google Identities
- Web UI Console for server access
- Admin and non-admin roles for web based access
- Admin role can be derived by nominating a field and specific value(s) in JWT claims
- Rest APIs for administration and user interfaces to the CA server
- Admin APIs can be called using API Key based authentication too

## Default Server Installation

### Requirements
- AWS DynamoDB table - The default implementation requires an AWS DynamoDB table for storage. DDB schema can be found in the ```ddb_schema``` directory.
- AWS Secrets Manager - AWS Secrets Manager for storage and retrieval of CA Signing Keys, encryption secrets for swoossh server.

### Server configuration options
The server requires a ```yaml``` based configuration file, a sample of which is provided. Below is an explanation of fields included in the YAML configuration -

##### CAServer
- Certificate Authority signer's private keys are to be supplied as AWS Secret Manager entries in the ```HostCertSignerKey``` and ```UserCertSignerKey``` sub-sections of the ```CAServer``` section of config file.
The default implementation expects the private key in the ```PEM``` format.
- ```CertMaxValidityDays``` section specifies lifetime of SSH certificates issued by the CA.

#### Storage
As mentioned above, default implementation of Swoossh uses AWS DynamoDB as the storage. The schema for the DDB table is provided in the ```ddb_schema``` directory.
- ```DDBTableName``` specifies name of the DDB table.
- ```GSIPosixIDIndexName```, ```GSIUUIDIndexName```, ```GSISecondaryGroupsIndexName```, ```GSINameIndexName```, ```GSIEmailIndexName```, ```GsiTypeIndexName``` specify the names of GSI tables of DDB table.

#### HTTP Server
This section specifies http server's configuration.
- ```OauthConfig``` section -
  - ```ClientID``` specifies the client ID of your OpenID client.
  - ```ClientSecret``` specifies the client secret path in AWS Secrets Manager. Please note that the entry in secret must be a single tuple json object with the key name ```"secret"``` and its value set to the OpenID secret value. For ex: ```{"secret": "my_oauth_client_secret"}```
  - ```Scopes``` section specifies the list of scopes that your OpenID client requires to obtain user identities from the IDP.
  - ```OauthCallBackHandlerPath``` is the path where user's are returned back with the authorization token to your server after a successful OpenID dance.
  - ```OauthStateParamName``` is the name of parameter used for storing OpenID state. Usually specified by your OpenID IDP.
  - ```OauthClaimsEntitlementsField``` is the name of the claims field among other OpenID Claims returned by your IDP to claim the user's role for the specific purpose of identifying the user's role in Swoossh. More in ```Roles in Swoossh``` section below.
  - ```OauthEndPointAuthURL```
  - ```OauthEndPointTokenURL```
  - ```OIDCIssuerURL```
- APIKeyCreds section -
  This section specifies the list of admin API key credentials. Each credential comprises of a keyID and a corresponding secret.
  - ```ApiKeyID``` specifies the keyID
  - ```ApiKeySecret``` specifies the secret's path in AWS Secrets Manager. Please note that the entry in secret must be a single tuple json object with the key name ```"secret"``` and its value set to the API Key value. For ex: ```{"secret": "my_api_key_value"}```
- ```ApiKeySignatureValiditySecs``` specifies in seconds the validity of API signature.
- ```ApiKeyAuthzReqHeader``` specifies the header where the admin API Key based Signature is passed
- ```CookieKey``` is the key value to lookup the cookie's value in requests to the server's web console.
- ```CookieSecret``` specifies the AWS Secrets Manager path to the secret used to sign cookie values. Please note that the entry in secret must be a single tuple json object with the key name ```"secret"``` and its value set to the cookie signing secret value. For ex: ```{"secret": "cookie_signing_secret"}```
- ```AdminUserClaimsMatches``` is the value of the admin user's claims to match in OpenID claims from the OIDC provider.
- ```AdminHomeTmplName``` is the template to be used for fetching the admin home page from swoossh server. Path should be relative to the server startup script.
- ```HomeTmplName``` is the template to be used for fetching normal user's home page. Path should be relative to the server startup script.

#### Roles
The default implementation supports two different roles - admin and a normal user.
Admin users are able to administer the server and users.
Normal users are able to download their SSH certificates, change their Unix Passwords (detailed below) and upload a new SSH Public key.

#### Obtaining user's role in OpenIDC claims
Setup the ```OauthClaimsEntitlementsField``` value to instruct swoossh server to look up the OpenID claim for corresponding value of the user.
For instance if ```OauthClaimsEntitlementsField``` value is set to ```"SwoosshRole"```, Swoossh will look for ```"SwoosshRole"``` field in OpenIDC claims in
list of claims obtained from the IDToken from the IDC. For a user to be considered as an administrator, the value of this field in the OpenIDC claims must match
to the value set for the ```AdminUserClaimsMatches``` field. For instance, if the ```"SwoosshRole"``` claims value returned for a user is ```"admin"```, Swoossh checks if
this value matches to the ```AdminUserClaimsMatches``` field's value defined in the config and only considers the user as admin, if there is a positive match.


### Administration

#### Adding new users
Admin roles can add new users using the API or through the web console.
Pls note that primary/secondary groups associated with the user need to be added in the gid:groupname format. For ex: ```1223:devops```

#### Adding new groups
Admin roles can add new groups using the API or through the web console.
Pls note that you are not required to add the user's primary group separately as it is done at the time of user addition.

#### Programmatic Access - Signing requests


#### Changing Password
The default implementation allows users to change password to their Posix account and sync it to hosts as part of their login sequence.
Swoossh's home interface has a field for users to input pre-generated shadow compatible password hashes. For ex: ```"openssl passwd -6 -salt xyz  yourpass"```

#### Changing publicKey
Users are allowed to rotate their SSH keys by uploading a new public key from their home page of Swoossh web interface. Certificates issued thereafter will have the new public key signed.


#### Creating the first admin user in DDBTable manually
To initialize swoossh and administer it, you will need to add an admin user manually to the DynamoDB table. Thereafter user administration can be done by logging in as that admin user over the web interface.
However if you are working off the Admin APIs using API Key based mechanism, you may administer the server without above requirement.

## Host preparation and Principals Command Installation

### Adding the CA public key in sshd config

### Environment variables
For Swoossh's principal command to create user upon first time login, it needs to authorize the user's account on the host
by comparing user's groups presented in certificate against owner entitlement on the host.
Owner entitlements can be sourced by way of an environment variable made available (to Swoossh command's RunAsUser) for lookup.
The name of this environment variable should be supplied as value to flag ```"en_key"``` of the principal's command.

### AWS EC2 tags
Alternatively, Swoossh can source host's entitlements from AWS EC2 tags.
Swoossh command looks for EC2 tags for key that matches the ```"en_key"``` value passed in flag.
More than

### RunAs User
The RunAs user to be provided in sshd configuration for principals command should have necessary privileges for Swoossh command to perform the tasks expected of it on the host.
For default installation of Swoossh command it means that the RunAs user account must have privileges to create users, groups and change user passwords.

# Customization

## Custom storage
If you wanted to use a different storage layer with Swoossh instead of the default, all you have to do is to implement the interfaces declared in ```storage/store.go```, ```storage/sshuserstore.go```, ```storage/sshgroupstore.go```, ```storage/sshcertstore.go``` and supply your implementation while creating DefaultHTTPServer in main swoossh file as -
```
srv := &httpserver.DefaultHTTPServer{
    Store:             myCustomStorage,
    ...
    ..
    .
```

## Custom Principals Command implementation
Interested in modifying the default principal command to suit your requirements? Implement the interfaces in ```host.go```, ```posixhost.go``` and ```sudo.go``` files in ```authorizedprincipals``` directory.
Call your implementation in the main.go file of ```cmd``` directory as -
```
func prepareHost(entitlementsKey string, targetUser string) (myCustomHost, error) {
    ...
    host := myCustomHost{
      ...
    }
    ...
    return myCustomHost, nil
}
```

# How does it work?
![swoossh working](https://github.com/ChandraNarreddy/swoossh/blob/724c62259a26f963cdc375f8ab8bfff3b10cfbd6/swoossh_workflow.svg)
Swoossh is opinionated in the way it does things
- Uses SSH Cert's extensions to carry payload about the user.
- Swoossh's principals command can create a non-existant user on the host after ascertaining that the user is authorized to login.
The authorization logic looks for at least one match among the user's primary/secondary groups presented in the certificate and the host system's entitlements (sourced from env_var or EC2 tags).
- Principals command ensures that the UID and GIDs of the user created are consistent across fleet.
- Principals command can create missing groups the user is associated with on the host
- Principals command can change the password of the user to the latest value

## Rough edges
Users trying to login to a host where their account is not already setup will be unable to authenticate to the host using their username as the target username (login_name).
This happens because under the SSH protocol, the login_name presented in the incoming connection must exist on the system before the connection can be passed through for further validation which includes certificate validation.
You can work your way around this. Here's how -
- When you login to a host that hasn't got your account setup yet, your login attempt will fail.
- This can either mean that your certificate is not valid or your account does not exist on that host (assuming the host is setup with Swoossh properly).
- Make sure you  have got yourself a valid certificate from Swoossh server console.
- Try logging in once again. If it succeeds, you had a bad certificate to blame. Life continues.
- But if the login attempt failed, it is very likely because your account does not exist on the host.
- Try changing the login_name (-l flag or the ```user``` part in ```user@host``` in your ssh connection command) value to
a generic user account name that is known to exist on your fleet.
For instance, ```nobody```, this account is likely to exist in all flavours of linux. Don't forget to pass your certificate along though
- Since the account exists on the host, SSH server allows the connection attempt and hands over the validation to Swoossh command once it verifies that the certificate is signed by a trusted CA.
Swoossh command validates whether the certificate is valid and if so, proceeds to create the user account presented in the certificate once authorization checks pass.
- Since the login_name does not match up to the username presented in the certificate, Swoossh command nevertheless rejects the login attempt but not before user account creation is done.
- Now try changing back your login_name back to your own user_name and attempt login.
Since the user account would have been created by Swoossh command during the previous attempt, your login should succeed.
If your login still fails, it means that user account did not happen in the last attempt.
It is likely that Swoossh failed to create your account because authorization checks failed.
Other reasons could be Swoossh command being mis-configured or not being properly installed on the host. You may have to reach your administrator for help.
