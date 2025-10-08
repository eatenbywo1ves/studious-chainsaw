#!/usr/bin/env python3
"""
GhidraSimilarity GPU-Accelerated API
Simple ML inference server for binary function similarity
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import torch
import torch.nn as nn
from datetime import datetime

app = FastAPI(
    title="GhidraSimilarity API",
    description="GPU-accelerated binary function similarity analysis",
    version="1.0.0"
)

# Simple similarity model (demo version)
class SimpleSimilarityEncoder(nn.Module):
    """Lightweight encoder for demo purposes."""

    def __init__(self, vocab_size: int = 1000, embedding_dim: int = 128):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embedding_dim)
        self.encoder = nn.LSTM(embedding_dim, 64, batch_first=True)
        self.projection = nn.Linear(64, 32)

    def forward(self, x):
        embedded = self.embedding(x)
        _, (hidden, _) = self.encoder(embedded)
        projected = self.projection(hidden.squeeze(0))
        return nn.functional.normalize(projected, p=2, dim=1)

# Global model (loaded on startup)
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = SimpleSimilarityEncoder().to(device)
model.eval()

# Request/Response models
class SimilarityRequest(BaseModel):
    function_name: str
    instructions: List[str]
    top_k: int = 10

class SimilarityMatch(BaseModel):
    function_name: str
    similarity_score: float

class SimilarityResponse(BaseModel):
    query_function: str
    similar_functions: List[SimilarityMatch]
    gpu_used: bool
    inference_time_ms: float

@app.get("/")
async def root():
    return {
        "service": "GhidraSimilarity API",
        "version": "1.0.0",
        "gpu_available": torch.cuda.is_available(),
        "gpu_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "N/A",
        "cuda_version": torch.version.cuda if torch.cuda.is_available() else "N/A"
    }

@app.get("/health")
async def health():
    """Health check endpoint."""
    gpu_ok = torch.cuda.is_available()
    return {
        "status": "healthy" if gpu_ok else "degraded",
        "gpu_available": gpu_ok,
        "timestamp": datetime.now().isoformat()
    }

@app.get("/metrics")
async def metrics():
    """Prometheus-compatible metrics."""
    gpu_available = 1 if torch.cuda.is_available() else 0
    gpu_memory_used = 0
    gpu_memory_total = 0

    if torch.cuda.is_available():
        gpu_memory_used = torch.cuda.memory_allocated(0) / (1024**3)  # GB
        gpu_memory_total = torch.cuda.get_device_properties(0).total_memory / (1024**3)  # GB

    metrics_text = f"""# HELP ghidra_similarity_gpu_available GPU availability
# TYPE ghidra_similarity_gpu_available gauge
ghidra_similarity_gpu_available {gpu_available}

# HELP ghidra_similarity_gpu_memory_used_gb GPU memory used in GB
# TYPE ghidra_similarity_gpu_memory_used_gb gauge
ghidra_similarity_gpu_memory_used_gb {gpu_memory_used:.2f}

# HELP ghidra_similarity_gpu_memory_total_gb Total GPU memory in GB
# TYPE ghidra_similarity_gpu_memory_total_gb gauge
ghidra_similarity_gpu_memory_total_gb {gpu_memory_total:.2f}
"""

    return metrics_text

@app.post("/api/similarity", response_model=SimilarityResponse)
async def compute_similarity(request: SimilarityRequest):
    """Compute function similarity using GPU acceleration."""

    try:
        import time
        start_time = time.time()

        # Simple tokenization (demo - in production use proper assembly tokenizer)
        tokens = [hash(inst) % 1000 for inst in request.instructions[:50]]
        if len(tokens) < 50:
            tokens.extend([0] * (50 - len(tokens)))  # Pad

        # Convert to tensor and move to GPU
        input_tensor = torch.tensor([tokens], dtype=torch.long).to(device)

        # Inference
        with torch.no_grad():
            model(input_tensor)

        # Mock database lookup (in production, compare against real function database)
        mock_results = [
            SimilarityMatch(function_name=f"similar_func_{i}", similarity_score=0.95 - i*0.05)
            for i in range(request.top_k)
        ]

        inference_time = (time.time() - start_time) * 1000  # ms

        return SimilarityResponse(
            query_function=request.function_name,
            similar_functions=mock_results,
            gpu_used=torch.cuda.is_available(),
            inference_time_ms=inference_time
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")

if __name__ == "__main__":
    import uvicorn

    print(f"Starting GhidraSimilarity API on device: {device}")
    print(f"GPU Available: {torch.cuda.is_available()}")

    if torch.cuda.is_available():
        print(f"GPU Name: {torch.cuda.get_device_name(0)}")
        print(f"CUDA Version: {torch.version.cuda}")

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
