FROM ustclug/debian:13
RUN apt update && apt -y upgrade && \
    apt install --no-install-recommends -y xinetd python3-nacl docker-cli python3-requests python3-requests-unixsocket python3-httpx && \
    rm -rf /var/lib/apt/lists/*
COPY main.py /
COPY pubkey /
COPY db.py /
COPY redirect.html /
COPY gocat /
RUN chmod +x /gocat
CMD ["python3", "main.py"]
