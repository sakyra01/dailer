FROM python:3.11-alpine

RUN apk add --no-cache git
CMD ["git","--version"]

WORKDIR /app
COPY app /app
RUN pip install --upgrade pip && pip install -r requirements.txt
ENTRYPOINT ["python3", "dailer.py"]