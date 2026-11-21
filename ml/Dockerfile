FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY ml/requirements.txt /app/ml/requirements.txt

RUN pip install --no-cache-dir --timeout 120 --retries 10 -r /app/ml/requirements.txt
COPY ml/api/ /app/ml/api/
COPY ml/inference/ /app/ml/inference/
COPY ml/models/web_coverage_candidate.joblib /app/ml/models/

CMD ["uvicorn", "ml.api.main:app", "--host", "0.0.0.0", "--port", "8000"]d