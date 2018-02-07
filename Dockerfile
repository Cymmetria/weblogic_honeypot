FROM python:2-alpine

COPY . /usr/src/app/
WORKDIR /usr/src/app

EXPOSE 8000

CMD ['python', 'weblogic_server.py']
