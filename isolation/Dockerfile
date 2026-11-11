# One image, two security domains. The broker and the worker never share a
# container, a network or the state volume; they only share this code.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# sgagent is the only thing both domains have in common: group access to the
# agent socket and to one task's token file.
RUN groupadd -g 10001 sgbroker && groupadd -g 10002 sgworker && groupadd -g 10003 sgagent \
 && useradd -u 10001 -g sgbroker -G sgagent -M -d /nonexistent -s /usr/sbin/nologin sgbroker \
 && useradd -u 10002 -g sgworker -G sgagent -M -d /home/worker -s /usr/sbin/nologin sgworker \
 && install -d -o sgbroker -g sgbroker -m 0700 /var/lib/secret-guard \
 && install -d -o sgbroker -g sgagent -m 2750 /run/secret-guard/agent /run/secret-guard/tasks

WORKDIR /opt/secret-guard
COPY requirements.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock
COPY secret_guard ./secret_guard
RUN pip install --no-cache-dir --no-build-isolation --no-deps . && rm -rf build *.egg-info
COPY isolation/egress_proxy.py isolation/bypass_probe.py isolation/fake_broker.py ./isolation/

USER sgworker
CMD ["python", "-c", "print('secret-guard isolated image; start through isolation/guardctl')"]
