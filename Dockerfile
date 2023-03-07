FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install -y libelf-dev

COPY ./src/debug /debug

ENTRYPOINT ["/debug"]