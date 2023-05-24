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

# Carla RSS python module
COPY --chown=carla:carla PythonAPI /home/carla/PythonAPI

# Entrypoint script
COPY --chown=carla:carla entrypoint.sh /home/carla/entrypoint.sh
ENTRYPOINT [ "/bin/bash", "-c", "/home/carla/entrypoint.sh" ]



