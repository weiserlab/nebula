# Dockerfile

# Use the official Python image as the base image
FROM python:3.9

# Copy external anonymous tokens repo into /ext/
WORKDIR /ext/anonymous-tokens
COPY _build/anonymous-tokens .

# Set the working directory for the application
WORKDIR /app

# Copy the requirements.txt file into the container
COPY requirements.txt .

# Install the required packages
RUN pip install --no-cache-dir -r requirements.txt

# Install nightly Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"
RUN rustup default nightly

# Copy the rest of the application code into the container
COPY . .

# Build python bindings for token library
RUN maturin build --manifest-path anonymous-tokens-lib/Cargo.toml --release --out ./anonymous_tokens_lib
RUN pip install --no-cache-dir anonymous_tokens_lib/anonymous_tokens_lib*.whl

# Expose the port the app runs on
EXPOSE $SERVER_PORT

# Set the environment variable for the server mode (provider or app)
ENV SERVER_MODE=provider

# Start the Uvicorn server with the specified server mode
CMD if [ "$SERVER_MODE" = "provider" ] ; then \
        # if SERVER_TLS is true, start the server with TLS
        if [ "$SERVER_TLS" = "true" ] ; then \
            uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --ssl-keyfile=/certs/key.pem --ssl-certfile=/certs/cert.pem --workers 1; \
        # otherwise, start the server without TLS
        else \
            uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --workers 1; \
        fi \
    else \
        if [ "$SERVER_TLS" = "true" ] ; then \
            uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --ssl-keyfile=/certs/key.pem --ssl-certfile=/certs/cert.pem --workers 1; \
        else \
            uvicorn main:app --host 0.0.0.0 --port $SERVER_PORT --workers 1; \
        fi \
    fi

