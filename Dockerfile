FROM python:3.8-alpine as build-stage
LABEL maintainer="je5r1ta@icloud.com"

ADD . /opt/ctf-wiki/
WORKDIR /opt/ctf-wiki
RUN pip install -r requirements.txt \
      && python scripts/docs.py build-all


FROM nginx:mainline-alpine
COPY --from=build-stage /opt/ctf-wiki/site /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
