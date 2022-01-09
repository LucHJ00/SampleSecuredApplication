# syntax=docker/dockerfile:1

From python:3.9.9-slim-bullseye

WORKDIR /python-docker

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt 

COPY . . 

CMD ["python3", "app.py"]
