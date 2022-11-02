ARG PYTHON_VERSION=3.9

FROM docker.io/python:${PYTHON_VERSION}-slim

# Install libmagic. We don't need to install libolm, because we're installing it with a
# wheel from gitlab.matrix.org later, which comes with libolm already compiled.
RUN apt-get update -qq && apt-get install -qq libmagic1

# Copy the necessary project files into the image.
COPY setup.cfg pyproject.toml /
COPY matrix_content_scanner /matrix_content_scanner/

# Install the project and its dependencies, using gitlab.matrix.org as the index. This is
# so we can get a python-olm wheel, which will have more recent bindings than the current
# version of python-olm on PyPI, and comes with libolm already compiled.
RUN pip install --index-url=https://gitlab.matrix.org/api/v4/projects/27/packages/pypi/simple .

# Create the directory in which long-lived configuration and secrets will live. We switch
# to it to ensure any automatically-generated secret is persisted when the container is
# destroyed.
RUN mkdir /data
WORKDIR /data

# Start the service using user-provided configuration.
ENTRYPOINT ["python", "-m", "matrix_content_scanner.mcs", "-c", "/data/config.yaml"]