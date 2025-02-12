FROM ubuntu:22.04

RUN apt update -y 

RUN apt-get install -y \
    default-jdk wget iperf3 iputils-ping

RUN wget https://dlcdn.apache.org/maven/maven-3/3.9.5/binaries/apache-maven-3.9.5-bin.tar.gz
RUN tar -xvf apache-maven-3.9.5-bin.tar.gz
RUN mv apache-maven-3.9.5 /opt/

ENV M2_HOME='/opt/apache-maven-3.9.5'
ENV PATH="$M2_HOME/bin:$PATH"

RUN export PATH

RUN mkdir /client

COPY ./client/ /client

RUN chmod +x /client/start.sh

WORKDIR /client

RUN mvn compile


