# This Dockerfile is a modified version of https://github.com/bskaggs/ghidra-docker/blob/master/Dockerfile

FROM eclipse-temurin:21-jdk
LABEL maintainer="anmarcel@cisco.com"
LABEL description="Ghidraaas - Ghidra 11.4.2 as a Service"

ARG GHIDRA_VERSION=11.4.2_PUBLIC_20250826
ARG GHIDRA_BUILD=Ghidra_11.4.2_build
ARG GHIDRA_SHA256=795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6

RUN useradd -m ghidra && \
    mkdir -p /srv/repositories && \
    chown -R ghidra: /srv/repositories
COPY --chown=ghidra:ghidra launch.sh.patch /tmp/

RUN apt-get update \
  && apt-get install -y python3-pip python3-dev \
  && apt-get install unzip \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --break-system-packages --ignore-installed --upgrade pip

RUN apt-get install -y libgtk2.0 libidn12 libglu1-mesa

WORKDIR /opt
RUN apt-get update && apt-get install -y wget gettext-base patch && \
    wget -q -O ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_BUILD}/ghidra_${GHIDRA_VERSION}.zip
RUN echo "${GHIDRA_SHA256} *ghidra.zip" | sha256sum -c && \
    unzip ghidra.zip && \
    rm ghidra.zip && \
    ln -s ghidra* ghidra && \
    cd ghidra && \
    patch -p0 < /tmp/launch.sh.patch && \ 
    rm -rf docs && \
    cd .. && \
    chown -R ghidra: ghidra*

COPY requirements.txt /opt/requirements.txt
RUN pip3 install --break-system-packages -r /opt/requirements.txt

# Create /opt/ghidraaas working folder
RUN mkdir -p /opt/ghidraaas
RUN chown ghidra:ghidra /opt/ghidraaas

RUN mkdir -p /opt/ghidra_projects
RUN chown ghidra:ghidra /opt/ghidra_projects

USER ghidra
WORKDIR /opt/ghidraaas

ENV ghidra_home=/opt/ghidra

COPY --chown=ghidra:ghidra flask_api.py flask_api.py
COPY --chown=ghidra:ghidra ghidra_plugins /opt/ghidra_plugins/

RUN mkdir /opt/ghidraaas/config
COPY --chown=ghidra:ghidra config/docker_config.json /opt/ghidraaas/config/config.json

ENTRYPOINT gunicorn -w 2 -t 300 -b 0.0.0.0:8080 flask_api:app
