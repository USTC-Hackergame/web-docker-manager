FROM ustclug/debian:13

ENV DEBIAN_FRONTEND noninteractive

RUN apt update && apt -y upgrade && \
    apt install -y python3 python3-pip

RUN pip install --no-cache-dir --break-system-packages flask

COPY example.py /
COPY templates /templates

USER nobody

CMD [ "python3", "example.py" ]
