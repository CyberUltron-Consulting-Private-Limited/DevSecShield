FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y git
RUN pip3 install git+https://github.com/GreyDGL/PentestGPT

