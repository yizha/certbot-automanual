# certbot-automanual
Letsencrypt certbot plugin, modified from the official manual plugin to automate challenge setup in an external web server with a given executable. The executable needs to accept two arguments (http-01 challenge uri and challenge content) and should set up the an external web server to make ready for the challenge. The executable needs to exit with a non-zero code in case of any error.

# Install (in most cases it requires root access)
```
# python2 setup.py install
```

# Example Usage (in most cases it requires root access as it writes to /var/lib/letsencrypt and /etc/letsencrypt)
## Run with a binary executable
```
# certbot certonly --non-interactive --agree-tos -a certbot-automanual:auth --automanual-auth-exec /tmp/set-up-web-server -d example.com --staging
```
## Run with a bash script as the executable
```
# certbot certonly --non-interactive --agree-tos -a certbot-automanual:auth --automanual-auth-exec /tmp/set-up-web-server.sh --automanual-auth-exec-interpreter /bin/bash -d example.com --staging
```
