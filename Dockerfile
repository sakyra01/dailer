FROM python:3.10.7-alpine

RUN apk add --no-cache git
CMD ["git","--version"]

WORKDIR /app
COPY app /app
RUN pip install --upgrade pip && pip install -r requirements.txt
ENTRYPOINT ["python3", "main.py"]
CMD ["ls logs/"]