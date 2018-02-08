FROM python:2-alpine

COPY requirements.txt /usr/src/app/requirements.txt
WORKDIR /usr/src/app
RUN pip install --no-cache -r requirements.txt

COPY . /usr/src/app/

EXPOSE 8000

CMD ['python', 'weblogic_server.py']
