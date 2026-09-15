# --- stage 1: build the UI -------------------------------------------------
# The frontend is a Vite + React app under frontend/. It is built here rather
# than copied from the host so the image is reproducible from source alone,
# and so nothing about running a case depends on a machine having node.
#
# This is the only stage that needs the network, and it needs it at BUILD
# time. Analysis itself never reaches out: every asset is bundled locally, so
# a case can be worked air-gapped (CLAUDE.md gotcha #17). npm ci installs the
# exact lockfile - the output of this tool is evidence, so the bundle has to
# be repeatable.
FROM node:22-slim AS frontend

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# vite.config.js sets outDir to ../static, i.e. /static in this stage.
RUN npm run build

# --- stage 2: the app ------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Built UI from stage 1, not the host's static/ - so an image never ships a
# stale bundle somebody forgot to rebuild.
COPY --from=frontend /static ./static
# Feed refresh runs inside the container (it is the only part that needs
# network access); analysis itself reads the downloaded files offline.
COPY tools ./tools

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
