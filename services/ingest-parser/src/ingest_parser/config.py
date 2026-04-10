"""
Configuration for the ingest-parser service.

All configuration is loaded from environment variables with sensible defaults.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ParserConfig:
    """Configuration for the document parser.

    Attributes:
        parser_name: Name of the parser backend (e.g., 'docling', 'marker')
        model_path: Path to the AI model weights directory
        expected_model_hash: Expected SHA256 hash of the model weights
        cpu_only: Force CPU execution for determinism (should always be True)
        num_threads: Number of CPU threads to use (1 for max reproducibility)
        bbox_precision: Decimal places for bounding box rounding
    """

    parser_name: str = "docling"
    model_path: Path = field(default_factory=lambda: Path("/models"))
    expected_model_hash: str = ""
    cpu_only: bool = True
    num_threads: int = 1
    bbox_precision: int = 4

    @classmethod
    def from_env(cls) -> ParserConfig:
        """Load configuration from environment variables."""
        return cls(
            parser_name=os.getenv("INGEST_PARSER_NAME", "docling"),
            model_path=Path(os.getenv("INGEST_PARSER_MODEL_PATH", "/models")),
            expected_model_hash=os.getenv("INGEST_PARSER_MODEL_HASH", ""),
            cpu_only=os.getenv("INGEST_PARSER_CPU_ONLY", "true").lower() == "true",
            num_threads=int(os.getenv("INGEST_PARSER_NUM_THREADS", "1")),
            bbox_precision=int(os.getenv("INGEST_PARSER_BBOX_PRECISION", "4")),
        )


@dataclass(frozen=True)
class ServerConfig:
    """Configuration for the HTTP server.

    Attributes:
        host: Host to bind to
        port: Port to listen on
        max_file_size_mb: Maximum upload file size in megabytes
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
        environment_digest: SHA256 hash of the Docker image or environment manifest
    """

    # Note: 0.0.0.0 binds to all interfaces, which is intentional for
    # containerized deployments. For production use behind a reverse proxy,
    # consider binding to 127.0.0.1 if the service should not be directly accessible.
    host: str = "0.0.0.0"
    port: int = 8090
    max_file_size_mb: int = 256
    log_level: str = "INFO"
    environment_digest: str = ""

    @classmethod
    def from_env(cls) -> ServerConfig:
        """Load configuration from environment variables."""
        return cls(
            host=os.getenv("INGEST_PARSER_HOST", "0.0.0.0"),
            port=int(os.getenv("INGEST_PARSER_PORT", "8090")),
            max_file_size_mb=int(os.getenv("INGEST_PARSER_MAX_FILE_SIZE_MB", "256")),
            log_level=os.getenv("INGEST_PARSER_LOG_LEVEL", "INFO"),
            environment_digest=os.getenv(
                "INGEST_PARSER_ENVIRONMENT_DIGEST",
                "sha256_0000000000000000000000000000000000000000000000000000000000000000",
            ),
        )

    @property
    def max_file_size_bytes(self) -> int:
        """Maximum file size in bytes."""
        return self.max_file_size_mb * 1024 * 1024


@dataclass(frozen=True)
class Config:
    """Complete service configuration."""

    parser: ParserConfig
    server: ServerConfig

    @classmethod
    def from_env(cls) -> Config:
        """Load complete configuration from environment variables."""
        return cls(
            parser=ParserConfig.from_env(),
            server=ServerConfig.from_env(),
        )


def enforce_cpu_only() -> None:
    """Enforce CPU-only execution for deterministic floating-point math.

    GPU floating-point math (CUDA/TensorCore) is non-deterministic across
    different hardware. This function ensures all computation runs on CPU
    with FP32 precision for reproducible results.

    This MUST be called before importing any ML libraries (torch, etc.).
    """
    import os

    # Disable CUDA completely
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"

    # Disable Apple Metal Performance Shaders
    os.environ["PYTORCH_ENABLE_MPS_FALLBACK"] = "0"

    # Disable TensorFlow GPU
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
    os.environ["TF_FORCE_GPU_ALLOW_GROWTH"] = "false"

    # Disable JAX GPU
    os.environ["JAX_PLATFORM_NAME"] = "cpu"

    # Disable OpenCL
    os.environ["OPENCL_CACHE_ENABLE"] = "0"


def configure_deterministic_execution(num_threads: int = 1) -> None:
    """Configure libraries for deterministic execution.

    This function configures NumPy, PyTorch, and other libraries for
    maximum reproducibility. Should be called after enforce_cpu_only().

    Args:
        num_threads: Number of CPU threads to use. Set to 1 for maximum
                     reproducibility (eliminates thread-ordering effects).
    """
    import os

    # Limit thread count for reproducibility
    os.environ["OMP_NUM_THREADS"] = str(num_threads)
    os.environ["MKL_NUM_THREADS"] = str(num_threads)
    os.environ["OPENBLAS_NUM_THREADS"] = str(num_threads)
    os.environ["VECLIB_MAXIMUM_THREADS"] = str(num_threads)
    os.environ["NUMEXPR_NUM_THREADS"] = str(num_threads)

    # Try to configure PyTorch if available
    try:
        import torch

        torch.set_num_threads(num_threads)
        torch.set_num_interop_threads(num_threads)

        # Enable deterministic algorithms
        torch.use_deterministic_algorithms(True, warn_only=True)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

    except ImportError:
        pass  # PyTorch not installed, skip configuration

    # Try to configure NumPy if available
    try:
        import numpy as np

        # Seed is not set here - each extraction should be deterministic
        # without needing a random seed
        np.seterr(all="raise")  # Raise on floating-point errors
    except ImportError:
        pass  # NumPy not installed, skip configuration
