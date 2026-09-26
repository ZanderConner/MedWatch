FROM python:3.12-slim

# openssh-server: lets an operator ssh/exec into the box during a live
# demo to fire rogue_traffic.py --once on demand, in addition to the
# background periodic loop that runs automatically.
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config

# Demo-range-only credential (same convention as OE_USER/OE_PASS and
# MYSQL_PASS elsewhere in demo/docker-compose.yml) — this box only ever
# sits on isolated internal Docker networks, never exposed to a host
# port, so a fixed demo password is consistent with the rest of the
# range's "hackathon simple" security posture, not a real secret.
ARG ROOT_PASSWORD=redteam
RUN echo "root:${ROOT_PASSWORD}" | chpasswd

WORKDIR /app
COPY rogue_traffic.py entrypoint.sh ./
RUN chmod +x entrypoint.sh

ENV PYTHONUNBUFFERED=1
EXPOSE 22

ENTRYPOINT ["./entrypoint.sh"]
