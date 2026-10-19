FROM python:3.13-slim
WORKDIR /lab
COPY app.py /lab/app.py
USER 65534:65534
EXPOSE 8080
CMD ["python", "-B", "/lab/app.py"]
