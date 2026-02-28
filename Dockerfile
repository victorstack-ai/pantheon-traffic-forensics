FROM python:3.12-slim

LABEL maintainer="Victor Jimenez"
LABEL description="Pantheon Traffic Forensics - access log spike triage"

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY sample/ sample/

RUN pip install --no-cache-dir .

ENTRYPOINT ["ptf"]
CMD ["--help"]
