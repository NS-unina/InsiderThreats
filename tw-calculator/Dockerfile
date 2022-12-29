FROM openjdk:slim-buster
RUN apt-get update && apt-get install -y git make

RUN git clone https://github.com/TCS-Meiji/PACE2017-TrackA.git
WORKDIR /PACE2017-TrackA
RUN make && chmod +x tw-exact
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT /entrypoint.sh