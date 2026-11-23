FROM python:3.13-alpine
WORKDIR /app
COPY app/ /app/
# /config holds settings.json (the connection set up in the first-run wizard).
RUN mkdir /config && chown 1000:1000 /config
ENV PORT=8097 CONFIG_DIR=/config PYTHONUNBUFFERED=1
VOLUME /config
EXPOSE 8097
USER 1000:1000
CMD ["python3", "/app/server.py"]
