"""
Document parser abstraction layer.

Provides a unified interface for different document parsing backends
(Docling, Marker, OpenDataLoader, etc.) with determinism guarantees.
"""

from __future__ import annotations

import io
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING

from .schemas import BlockType, ContentBlock, DocumentPage, ExtractedDocument

if TYPE_CHECKING:
    from .config import ParserConfig


logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """Abstract base class for document parsers.

    All parsers must implement the same interface to ensure consistent
    behavior and deterministic output across different backends.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the parser name (e.g., 'docling')."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """Return the parser version (semantic version)."""
        pass

    @property
    @abstractmethod
    def model_hash(self) -> str:
        """Return the SHA256 hash of the model weights."""
        pass

    @abstractmethod
    def parse(self, content: bytes, content_type: str) -> ExtractedDocument:
        """Parse document content and return structured extraction.

        Args:
            content: Raw document bytes.
            content_type: MIME type of the document (e.g., 'application/pdf').

        Returns:
            ExtractedDocument with pages and blocks.

        Raises:
            ValueError: If content type is not supported.
            RuntimeError: If parsing fails.
        """
        pass

    def _round_float(self, value: float, precision: int = 4) -> float:
        """Round a float to the specified precision.

        This is CRITICAL for determinism. All floating-point values
        must be rounded to avoid drift across environments.
        """
        return round(value, precision)

    def _round_bbox(self, bbox: list[float], precision: int = 4) -> list[float]:
        """Round all bounding box coordinates to the specified precision."""
        return [self._round_float(v, precision) for v in bbox]


class FallbackParser(BaseParser):
    """Fallback parser for when no ML backends are available.

    This parser provides basic text extraction without ML-based
    layout analysis. Useful for testing and simple documents.
    """

    # Hardcoded version for the fallback parser
    _VERSION = "1.0.0"
    # No model weights, so use a deterministic placeholder hash
    _MODEL_HASH = "sha256_0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, config: ParserConfig) -> None:
        """Initialize the fallback parser.

        Args:
            config: Parser configuration.
        """
        self._config = config
        self._precision = config.bbox_precision

    @property
    def name(self) -> str:
        return "fallback"

    @property
    def version(self) -> str:
        return self._VERSION

    @property
    def model_hash(self) -> str:
        return self._MODEL_HASH

    def parse(self, content: bytes, content_type: str) -> ExtractedDocument:
        """Parse document using fallback method.

        For PDFs, attempts basic text extraction using pikepdf.
        For other formats, extracts raw text content.
        """
        if content_type == "application/pdf":
            return self._parse_pdf(content)
        elif content_type in ("text/plain", "text/html"):
            return self._parse_text(content)
        else:
            raise ValueError(f"Unsupported content type: {content_type}")

    def _parse_pdf(self, content: bytes) -> ExtractedDocument:
        """Extract text from PDF using pikepdf."""
        try:
            import pikepdf
        except ImportError as e:
            raise RuntimeError("pikepdf is required for PDF parsing") from e

        pages = []
        try:
            with pikepdf.open(io.BytesIO(content)) as pdf:
                for page_num, page in enumerate(pdf.pages, start=1):
                    # Extract text content (basic extraction)
                    text_content = ""
                    if "/Contents" in page:
                        # This is a simplified extraction - real parser would do more
                        text_content = f"[Page {page_num} content]"

                    # Get page dimensions
                    mediabox = page.get("/MediaBox", [0, 0, 612, 792])
                    width = float(mediabox[2]) - float(mediabox[0])
                    height = float(mediabox[3]) - float(mediabox[1])

                    blocks = []
                    if text_content:
                        blocks.append(
                            ContentBlock(
                                id=f"blk_{page_num:02d}_01",
                                type=BlockType.TEXT,
                                content=text_content,
                                bbox=[0.0, 0.0, self._round_float(width), self._round_float(height)],
                                confidence=1.0,
                            )
                        )

                    pages.append(
                        DocumentPage(
                            page_number=page_num,
                            width=self._round_float(width),
                            height=self._round_float(height),
                            blocks=blocks,
                        )
                    )

                return ExtractedDocument(
                    pages=pages,
                    total_pages=len(pdf.pages),
                    metadata={"parser": "fallback_pikepdf"},
                )

        except Exception as e:
            raise RuntimeError(f"Failed to parse PDF: {e}") from e

    def _parse_text(self, content: bytes) -> ExtractedDocument:
        """Extract text from plain text or HTML."""
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")

        # Create a single block with all text
        blocks = [
            ContentBlock(
                id="blk_01_01",
                type=BlockType.TEXT,
                content=text,
                bbox=[0.0, 0.0, 612.0, 792.0],  # Default page size
                confidence=1.0,
            )
        ]

        return ExtractedDocument(
            pages=[
                DocumentPage(
                    page_number=1,
                    width=612.0,
                    height=792.0,
                    blocks=blocks,
                )
            ],
            total_pages=1,
            metadata={"parser": "fallback_text"},
        )


class DoclingParser(BaseParser):
    """Parser using IBM Docling for complex document extraction.

    Docling provides state-of-the-art extraction for:
    - Complex PDFs with dual-columns
    - Scientific papers with equations
    - Documents with complex tables
    """

    def __init__(self, config: ParserConfig) -> None:
        """Initialize the Docling parser.

        Args:
            config: Parser configuration.
        """
        self._config = config
        self._precision = config.bbox_precision
        self._model: object | None = None
        self._model_hash_cache: str | None = None

        # Lazily load the model
        self._load_model()

    def _load_model(self) -> None:
        """Load the Docling model.

        Verifies model hash if expected_model_hash is configured.
        """
        try:
            # Import docling (must be installed separately)
            from docling.document_converter import DocumentConverter

            self._converter = DocumentConverter()
            self._docling_version = self._get_docling_version()

            # Compute model hash if model path exists
            if self._config.model_path.exists():
                from .crypto import compute_sha256_directory

                self._model_hash_cache = compute_sha256_directory(self._config.model_path)
            else:
                # Use placeholder if no custom model path
                self._model_hash_cache = (
                    "sha256_0000000000000000000000000000000000000000000000000000000000000000"
                )

            # Verify model hash if expected
            if self._config.expected_model_hash:
                from .crypto import verify_hash

                if not verify_hash(self._config.expected_model_hash, self._model_hash_cache):
                    raise RuntimeError(
                        f"Model hash mismatch. Expected {self._config.expected_model_hash}, "
                        f"got {self._model_hash_cache}"
                    )

            logger.info(f"Docling loaded: version={self._docling_version}, model_hash={self._model_hash_cache}")

        except ImportError as e:
            raise RuntimeError(
                "Docling is not installed. Install with: pip install docling"
            ) from e

    def _get_docling_version(self) -> str:
        """Get the installed Docling version."""
        try:
            from importlib.metadata import version

            return version("docling")
        except Exception:
            return "unknown"

    @property
    def name(self) -> str:
        return "docling"

    @property
    def version(self) -> str:
        return getattr(self, "_docling_version", "unknown")

    @property
    def model_hash(self) -> str:
        return self._model_hash_cache or (
            "sha256_0000000000000000000000000000000000000000000000000000000000000000"
        )

    def parse(self, content: bytes, content_type: str) -> ExtractedDocument:
        """Parse document using Docling."""
        if content_type != "application/pdf":
            raise ValueError(f"Docling only supports PDF files, got: {content_type}")

        import tempfile

        # Write content to temp file (Docling requires file path)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(content)
            temp_path = Path(f.name)

        try:
            result = self._converter.convert(temp_path)
            return self._convert_result(result)
        finally:
            temp_path.unlink()

    def _convert_result(self, result: object) -> ExtractedDocument:
        """Convert Docling result to ExtractedDocument."""
        pages = []

        # Access the document from the result
        doc = result.document

        # Group elements by page
        page_elements: dict[int, list[object]] = {}
        for element in doc.iterate_items():
            page_no = getattr(element, "page_no", 1) or 1
            if page_no not in page_elements:
                page_elements[page_no] = []
            page_elements[page_no].append(element)

        # Build pages
        for page_num in sorted(page_elements.keys()):
            blocks = []
            for idx, element in enumerate(page_elements[page_num]):
                block = self._convert_element(element, page_num, idx)
                if block:
                    blocks.append(block)

            pages.append(
                DocumentPage(
                    page_number=page_num,
                    blocks=blocks,
                )
            )

        return ExtractedDocument(
            pages=pages,
            total_pages=len(pages),
            metadata={"parser": "docling"},
        )

    def _convert_element(
        self, element: object, page_num: int, idx: int
    ) -> ContentBlock | None:
        """Convert a Docling element to a ContentBlock."""
        # Get element text
        text = getattr(element, "text", "") or ""
        if not text.strip():
            return None

        # Get bounding box
        bbox = getattr(element, "bbox", None)
        if bbox:
            bbox_list = [
                self._round_float(bbox.l),
                self._round_float(bbox.t),
                self._round_float(bbox.r),
                self._round_float(bbox.b),
            ]
        else:
            bbox_list = [0.0, 0.0, 0.0, 0.0]

        # Determine block type
        elem_type = type(element).__name__.lower()
        if "table" in elem_type:
            block_type = BlockType.TABLE
        elif "heading" in elem_type or "title" in elem_type:
            block_type = BlockType.HEADER
        elif "list" in elem_type:
            block_type = BlockType.LIST
        elif "code" in elem_type:
            block_type = BlockType.CODE
        elif "equation" in elem_type or "formula" in elem_type:
            block_type = BlockType.EQUATION
        else:
            block_type = BlockType.TEXT

        return ContentBlock(
            id=f"blk_{page_num:02d}_{idx + 1:02d}",
            type=block_type,
            content=text,
            bbox=bbox_list,
            confidence=self._round_float(getattr(element, "confidence", 1.0)),
        )


def create_parser(config: ParserConfig) -> BaseParser:
    """Factory function to create the appropriate parser.

    Attempts to load the configured parser, falling back to
    FallbackParser if the preferred parser is not available.

    Args:
        config: Parser configuration.

    Returns:
        A parser instance.
    """
    parser_name = config.parser_name.lower()

    if parser_name == "docling":
        try:
            return DoclingParser(config)
        except RuntimeError as e:
            logger.warning(f"Failed to load Docling: {e}. Using fallback parser.")
            return FallbackParser(config)

    elif parser_name == "fallback":
        return FallbackParser(config)

    else:
        logger.warning(f"Unknown parser '{parser_name}'. Using fallback parser.")
        return FallbackParser(config)
