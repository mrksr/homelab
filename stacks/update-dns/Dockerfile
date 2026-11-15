FROM python:3.13-alpine

COPY --from=ghcr.io/astral-sh/uv:0.13.8 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY update_dns.py .

RUN adduser -D -u 1000 app && mkdir /data && chown app /data
USER app
VOLUME /data
ENTRYPOINT ["/app/.venv/bin/python", "update_dns.py"]
