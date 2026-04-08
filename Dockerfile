FROM python:3.12-slim

WORKDIR /app

# Install dependencies first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose the standard Hugging Face Spaces port
EXPOSE 7860

# Run the FastAPI server using the server package
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "7860"]
