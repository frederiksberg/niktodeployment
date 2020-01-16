FROM alpine:3.10.0

RUN apk update \
    && apk add --no-cache \
        perl \
        perl-net-ssleay \
        git \
        busybox-suid \
    && git clone https://github.com/sullo/nikto /nikto \
    && rm -rf /var/cache/apk/* \
    && addgroup nikto \
    && adduser -G nikto -g "Nikto user" -s /bin/sh -D nikto \
    && chown -R nikto:nikto /nikto \
    && export RANDOM_PASSWORD=`tr -dc A-Za-z0-9 < /dev/urandom | head -c44` \
    && echo "root:$RANDOM_PASSWORD" | chpasswd \
    && unset RANDOM_PASSWORD \
    && passwd -l root

COPY ["cron", "/etc/crontabs/nikto"]

RUN chmod 644 /etc/crontabs/nikto

CMD ["crond", "-f", "-d", "8"]
