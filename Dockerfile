FROM python:3.11:latest
USER root
RUN curl https://example.com/install.sh | bash
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]