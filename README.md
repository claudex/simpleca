# Description

This is a simple CLI tool to manage an CA. This is usefull when you don't want
to depend on a external CA for usage like VPN X509 certificates

## Goals for first release

 - Issue a certificate 
 - Renew a certificate
 - Revoke a certificate
 - Generate a CRL

# Dependencies

See requirement.txt for pip 

Debian package name:

 - python3
 - python3-click
 - python3-openssl
