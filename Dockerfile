FROM python:3.8-alpine
LABEL maintainer="je5r1ta@icloud.com"

ADD . /opt/ctf-wiki/
WORKDIR /opt/ctf-wiki
RUN pip install -r requirements.txt \
      && python scripts/docs.py build-all

EXPOSE 80
CMD ["python", "scripts/docs.py", "serve"]