#!/bin/bash

# Builds caddy using xcaddy when using the caddy LXC, where go is not on the
# default path; also implements the custom build as an alternative to allow
# easier switching back to built-in caddy.

PATH="$PATH:/usr/local/bin"

if [ ! -f lxcaddy.args ]; then
    echo "Creating lxcaddy.args, edit to configure included modules. File contents are passed as arguments to xcaddy."
    touch lxcaddy.args
fi

cat lxcaddy.args | xargs xcaddy build

mv ./caddy /usr/bin/caddy.custom

if [ ! -f /usr/bin/caddy.default ]; then
    # https://caddyserver.com/docs/build#package-support-files-for-custom-builds-for-debianubunturaspbian
    dpkg-divert --divert /usr/bin/caddy.default --rename /usr/bin/caddy
    update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.default 10
    update-alternatives --install /usr/bin/caddy caddy /usr/bin/caddy.custom 50
fi

systemctl restart caddy
