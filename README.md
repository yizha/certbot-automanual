# certbot-external
Letsencrypt certbot plugin, modified from the official manual plugin to automate challenge setup and/or cert installation with given executable(s). Since it is from the official manual plugin, it only supports the HTTP01 challenge.

## My use case
Letsencrypt and certbot is great but it certainly cannot cover all possible use cases and that's why it supports plugins and for my case the cert is installed on an ELB with multiple EC2 instances behind it. So to automate the cert renew process we need do the following,
1. Generate challenge path and content (certbot)
2. Save the challenge content as a file on each of the EC2 instances behind the ELB (this plugin and a bash script)
3. Perform authentication and generate cert (certbot)
4. Install the cert to ELB (this plugin and an bash script)

## Install (in most cases it requires root access)
```
# python2 setup.py install
```

## Authenticator Options
* -a certbot-external:auth, specify to authenticate domain with this plugin
* --external-auth-exec [path], the executable file, required, could be binary or any type of script that comes with an interpreter (bash, python, ruby, lua, etc), the executable is called with two arguments: challenge uri (no domain, example /.well-known/acme-challenge/xxxxxxxxxx) and challenge content.
* --external-auth-exec-interpreter [path], required if exec is a script, for example if it is bash script, this interpreter option should given value /bin/bash, or /usr/bin/python if it is a python script.

## Installer Options
* -i certbot-external:install, specify to install cert with this plugin
* --external-install-exec [path], same as --external-auth-exec, the executable is called with five arguments: domain_name, cert_path, key_path, chain_path and fullchain_path.
* --external-install-exec-interpreter [path], same as --external-auth-exec-interpreter

## Examples (in most cases it requires root access as it writes to /var/lib/letsencrypt and /etc/letsencrypt)
### 'certbot certonly' with a binary executable
```
# certbot certonly --staging -n --agree-tos -a certbot-external:auth --external-auth-exec /tmp/set-up-web-server -d example.com
```
### 'certbot certonly' with a bash script
```
# certbot certonly --staging -n --agree-tos -a certbot-external:auth --external-auth-exec /tmp/set-up-web-server.sh --external-auth-exec-interpreter /bin/bash -d example.com
```
### 'certbot install' with a bash script
```
# certbot install --staging -n --agree-tos -i certbot-external:install --external-install-exec /tmp/install-cert.sh --external-install-exec-interpreter /bin/bash -d example.com
```
### 'certbot run' with two scripts, one to set up the web server, the other to install the cert
```
# certbot run --staging -n --agree-tos -a certbot-external:auth --external-auth-exec /tmp/set-up-web-server.sh --external-auth-exec-interpreter /bin/bash -i certbot-external:install --external-install-exec /tmp/install-cert.sh --external-install-exec-interpreter /bin/bash -d example.com
```
