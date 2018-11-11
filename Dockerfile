FROM python:3.6 as build-stage
MAINTAINER Yibai Zhang <xm1994@gmail.com>

ADD . /opt/ctf-wiki/
WORKDIR /opt/ctf-wiki
RUN pip install -r requirements.txt && ./build.sh

FROM alpine:3.8
RUN apk add --update --no-cache \
	lighttpd \
    && rm -rf /var/cache/apk/*

COPY --from=build-stage /opt/ctf-wiki/site /var/www/localhost/htdocs
EXPOSE 80
CMD ["lighttpd", "-D", "-f", "/etc/lighttpd/lighttpd.conf"]

