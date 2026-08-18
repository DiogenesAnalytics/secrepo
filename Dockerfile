# jupyter base image
FROM ghcr.io/diogenesanalytics/scipy-notebook:master AS jupyter

# first turn off git safe.directory
RUN git config --global safe.directory '*'

# turn off poetry venv
ENV POETRY_VIRTUALENVS_CREATE=false

# set src target dir
WORKDIR /usr/local/src/secrepo

# get src
COPY . .

# config max workers
RUN poetry config installer.max-workers 10

# now install source
RUN poetry install

# test base image
FROM python:3.11.8 AS testing

# install pyenv
RUN curl https://pyenv.run | bash

# set PYENV environment variables
ENV PYENV_ROOT="/root/.pyenv"
ENV PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"

# ensure pyenv is initialized properly
RUN echo 'export PYENV_ROOT="/root/.pyenv"' >> ~/.bashrc \
    && echo 'export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"' >> ~/.bashrc \
    && echo 'eval "$(pyenv init --path)"' >> ~/.bashrc \
    && echo 'eval "$(pyenv init -)"' >> ~/.bashrc

# turn off poetry venv
ENV POETRY_VIRTUALENVS_CREATE=false

# set src target dir
WORKDIR /usr/local/src/secrepo

# get src
COPY . .

# get poetry
RUN pip install poetry

# config max workers
RUN poetry config installer.max-workers 10

# now install development dependencies
RUN poetry install --with dev -C .

# final stage to run nox setup
FROM testing AS final

# Run nox to set up Python versions
RUN nox -s setup_python
