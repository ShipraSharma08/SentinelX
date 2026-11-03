
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ml.inference.predict import _load_model, predict_flow

app = FastAPI(
    title="SentinelX ML Inference API",
    description="Network-flow attack classification using the trained model.",
    version="1.0.0",
)


class PredictionRequest(BaseModel):
    features: dict[str, float] = Field(
        ...,
        description="Numeric network-flow features expected by the trained model.",
    )


class PredictionResponse(BaseModel):
    prediction: str
    attack_probability: float
    model: str


@app.get("/health")
def health():
    """Check whether the API and trained model are ready."""
    try:
        _load_model()
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="Trained ML model is unavailable.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="ML model could not be loaded.",
        ) from exc

    return {
        "status": "healthy",
        "model_ready": True,
        "service": "sentinelx-ml",
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(request: PredictionRequest):
    """Classify one network flow as BENIGN or ATTACK."""
    try:
        result = predict_flow(request.features)
        return PredictionResponse(**result)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="Trained ML model is unavailable.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Prediction failed unexpectedly.",
        ) from exc
