FROM python:3.12-slim

WORKDIR /app

# Prevent Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevent Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Copy required files for installation
COPY pyproject.toml README.md ./
COPY backend/ ./backend/
COPY cli/ ./cli/
COPY data/ ./data/

# WeasyPrint runtime libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgobject-2.0-0 libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 libffi-dev shared-mime-info \
 && rm -rf /var/lib/apt/lists/*

# Install dependencies (using --no-cache-dir to reduce image size)
RUN pip install --no-cache-dir .

EXPOSE 8000

# Default command (used in prod, overridden in dev)
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
