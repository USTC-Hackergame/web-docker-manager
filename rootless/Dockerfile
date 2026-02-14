FROM debian:trixie

RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get clean -y

RUN apt-get install -y util-linux bash-completion systemd systemd-container sudo iproute2 && \
    apt-get clean -y

ENV container=docker

RUN apt-get install -y ca-certificates curl && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && \
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && \
    systemctl disable docker.service docker.socket containerd.service

RUN useradd -m -s /bin/bash rootless

RUN apt-get install -y uidmap

ADD root-files /

ADD --chown=1000:1000 home-files /home/rootless

ENTRYPOINT [ "/usr/bin/entrypoint.sh" ]