# --- stage 1: build the UI -------------------------------------------------
# The frontend is a Vite + React app under frontend/. It is built here rather
# than copied from the host so the image is reproducible from source alone,
# and so nothing about running a case depends on a machine having node.
#
# This stage and the sigma stage below need the network, at BUILD time
# only. Analysis itself never reaches out: every asset is bundled locally, so
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

# --- stage 2: SigmaHQ's Windows rules, converted to SQL ---------------------
# specs/sigma_windows.md S-D3. A pinned SigmaHQ commit's archive, checked by its SHA-256
# (two downloads, 2026-10-29, gave the same bytes; if GitHub ever re-packs it the build
# fails here instead of converting other rules), converted by pySigma into the SQL the app
# runs. Fetching by git hash was tried first: BuildKit's fetch of the repository failed
# mid-transfer after 9 minutes. Like the UI, the network is needed at build time only;
# the app never imports pySigma. A new SigmaHQ commit is a new pin, checksum and baseline.
FROM python:3.12-slim AS sigma

ARG SIGMA_COMMIT=05d1031f537e830b76da53bae2400c5814c89165
WORKDIR /build
COPY requirements-sigma.txt .
RUN pip install --no-cache-dir -r requirements-sigma.txt
ADD --checksum=sha256:d88ab53693011ae9fe0681c5d8eecc07587d145a519a7f7fb0f4e208b2e6368c \
    https://github.com/SigmaHQ/sigma/archive/${SIGMA_COMMIT}.tar.gz /build/sigma.tar.gz
RUN mkdir /sigma && tar -xzf sigma.tar.gz -C /sigma --strip-components=1 && rm sigma.tar.gz
COPY tools/sigma_build.py .
RUN python sigma_build.py /sigma /out/windows_rules.json --commit ${SIGMA_COMMIT}

# --- stage 3: the app ------------------------------------------------------
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
# Built UI from stage 1, not the host's static/ - so an image never ships a
# stale bundle somebody forgot to rebuild.
COPY --from=frontend /static ./static
# Outside app/: the dev compose mounts ./app over /app/app, which would hide it.
COPY --from=sigma /out /opt/sigma
# Feed refresh runs inside the container (it is the only part that needs
# network access); analysis itself reads the downloaded files offline.
COPY tools ./tools

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
