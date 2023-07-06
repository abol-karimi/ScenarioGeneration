# syntax=docker/dockerfile:1

FROM carlasim/carla:0.9.14

USER root

# prerequisites
RUN apt-get update ; \
  apt-get install -y python3 python3-dev python3-pip python3-numpy cython3 python3-pyproj python3-cffi python3-cffi-backend \
  build-essential \
  gcc clang bison re2c cmake \ 
  python3.8 \
  python3.8-dev \
  python3.8-venv \
  curl \
  git \
  fontconfig \
  fonts-freefont-ttf \
  libjpeg-turbo8 \
  libjpeg-turbo8-dev \
  python3-pil \
  libtbb2 \
  eog \
  vim

USER carla
WORKDIR /home/carla

# Setup python environment
RUN python3 -m pip install --upgrade pip ; \
  python3.8 -m pip install --upgrade pip ; \
  python3.8 -m venv .venv ; \
  . .venv/bin/activate ; \
  python -m pip install --upgrade pip

# Build Clingo with Python support
RUN pip3 install --upgrade cmake ; \
  git clone --depth 1 --branch v5.4.1 https://github.com/potassco/clingo.git
WORKDIR /home/carla/clingo
RUN git submodule update --init --recursive ; \
  . /home/carla/.venv/bin/activate ; \
  cmake -H~/clingo -B~/clingo-build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=~/clingo-install \
  -DCLINGO_BUILD_APPS=ON \
  -DCLINGO_BUILD_SHARED=ON \
  -DCLINGO_BUILD_WITH_PYTHON=ON \
  -DCLINGO_PYTHON_VERSION:LIST="3.8;EXACT" \
  -DPython_ROOT=/home/carla/.venv \
  -DPYCLINGO_INSTALL_DIR=/home/carla/.venv/lib/python3.8/site-packages ; \
  cmake --build ~/clingo-build ; \
  cmake --build ~/clingo-build --target install

# Carla RSS python module
COPY --chown=carla:carla PythonAPI /home/carla/PythonAPI

# Entrypoint script
COPY --chown=carla:carla entrypoint.sh /home/carla/entrypoint.sh
ENTRYPOINT [ "/bin/bash", "-c", "/home/carla/entrypoint.sh" ]



