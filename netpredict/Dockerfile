FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY netpredict/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir -r requirements.txt

COPY netpredict/api.py ./api.py
COPY netpredict/src ./src
COPY netpredict/models ./models
COPY netpredict/data/processed ./data/processed

EXPOSE 8000

CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]