ARG PYTHON_VERSION=3.11

FROM docker.io/python:${PYTHON_VERSION}-slim AS requirements


# We install poetry in its own build stage to avoid its dependencies conflicting.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --user "poetry==1.8.3"

WORKDIR /mcs

# Copy just what we need to run `poetry export`...
COPY pyproject.toml poetry.lock /mcs/

# If specified, we won't verify the hashes of dependencies.
# This is only needed if the hashes of dependencies cannot be checked for some
# reason, such as when a git repository is used directly as a dependency.
ARG TEST_ONLY_SKIP_DEP_HASH_VERIFICATION

# If specified, we won't use the Poetry lockfile.
# Instead, we'll just install what a regular `pip install` would from PyPI.
ARG TEST_ONLY_IGNORE_POETRY_LOCKFILE

# Export the dependencies, but only if we're actually going to use the Poetry lockfile.
# Otherwise, just create an empty requirements file so that the Dockerfile can
# proceed.
RUN if [ -z "$TEST_ONLY_IGNORE_POETRY_LOCKFILE" ]; then \
  /root/.local/bin/poetry export -o /mcs/requirements.txt ${TEST_ONLY_SKIP_DEP_HASH_VERIFICATION:+--without-hashes}; \
  else \
  touch /mcs/requirements.txt; \
  fi

###
### Stage 1: builder
###
FROM docker.io/library/python:${PYTHON_VERSION}-slim AS builder

RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update -qq && apt-get install -yqq \
  build-essential \
  curl

# Install rust and ensure its in the PATH
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
RUN mkdir /rust /cargo

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal

# To speed up rebuilds, install all of the dependencies before we copy over
# the whole project, so that this layer in the Docker cache can be
# used while you develop on the source
#
# This is aiming at installing the `[tool.poetry.depdendencies]` from pyproject.toml.
COPY --from=requirements /mcs/requirements.txt /mcs/
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --prefix="/install" --no-deps --no-warn-script-location -r /mcs/requirements.txt

COPY src /mcs/src/
COPY rust /mcs/rust/
# ... and what we need to `pip install`.
COPY pyproject.toml README.md setup.cfg build_rust.py Cargo.toml Cargo.lock /mcs/

# Repeat of earlier build argument declaration, as this is a new build stage.
ARG TEST_ONLY_IGNORE_POETRY_LOCKFILE

# Install the matrix content scanner package itself.
# If we have populated requirements.txt, we don't install any dependencies
# as we should already have those from the previous `pip install` step.
RUN --mount=type=cache,target=/mcs/target,sharing=locked \
  --mount=type=cache,target=${CARGO_HOME}/registry,sharing=locked \
  if [ -z "$TEST_ONLY_IGNORE_POETRY_LOCKFILE" ]; then \
  pip install --prefix="/install" --no-deps --no-warn-script-location /mcs; \
  else \
  pip install --prefix="/install" --no-warn-script-location /mcs; \
  fi

###
### Stage 2: runtime
###

FROM docker.io/library/python:${PYTHON_VERSION}-slim

# Install libmagic & other useful tools.
# We don't need to install libolm, because we're installing it with a
# wheel from gitlab.matrix.org later, which comes with libolm already compiled.
RUN apt-get update -qq && apt-get install -qq libmagic1 c-icap && rm -rf /var/lib/apt/lists/*

# Copy the necessary project files into the image.
COPY --from=builder /install /usr/local

# Create the directory in which long-lived configuration and secrets will live. We switch
# to it to ensure any automatically-generated secret is persisted when the container is
# destroyed.
RUN mkdir /data
WORKDIR /data

# Start the service using user-provided configuration.
ENTRYPOINT ["python", "-m", "matrix_content_scanner.mcs", "-c", "/data/config.yaml"]
