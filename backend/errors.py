"""Error handling and response formatting."""

from fastapi import HTTPException, status
from typing import Any, Optional

class AppError(HTTPException):
    """Base application error."""
    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail: str = "Internal server error",
        code: Optional[str] = None,
        data: Optional[dict] = None,
    ):
        self.code = code
        self.data = data or {}
        super().__init__(status_code=status_code, detail=detail)

class ValidationError(AppError):
    """Input validation error."""
    def __init__(self, detail: str, code: str = "VALIDATION_ERROR", data: Optional[dict] = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            code=code,
            data=data,
        )

class NotFoundError(AppError):
    """Resource not found."""
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
            code="NOT_FOUND",
        )

class UnauthorizedError(AppError):
    """Authentication failed."""
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            code="UNAUTHORIZED",
        )

class ForbiddenError(AppError):
    """Authorization failed."""
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            code="FORBIDDEN",
        )

class ProcessingError(AppError):
    """Processing/service error."""
    def __init__(self, detail: str, code: str = "PROCESSING_ERROR"):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            code=code,
        )

def error_response(status_code: int, detail: str, code: str = "", data: dict = None):
    """Format error response."""
    return {
        "error": {
            "code": code,
            "message": detail,
            "data": data or {}
        }
    }
