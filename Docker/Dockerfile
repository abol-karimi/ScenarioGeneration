# syntax=docker/dockerfile:1

FROM carlasim/carla:0.9.13

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

# Set up Carla
RUN . ~/.venv/bin/activate ; \
  python -m pip install carla==0.9.13

# Set up Scenic
RUN git clone https://github.com/BerkeleyLearnVerify/Scenic.git
WORKDIR /home/carla/Scenic
RUN . ~/.venv/bin/activate ; \
  pip install cython ; \
  pip install numpy scipy pybind11 wheel; \
  python -m pip install -e .

# Binary version of Z3 to be used by PySMT
WORKDIR /home/carla
COPY --chown=carla:carla z3-4.8.10-x64-ubuntu-18.04 /home/carla/z3-4.8.10-x64-ubuntu-18.04
RUN  echo "\n" >> .bashrc ; \
  echo 'export PATH=$HOME/z3-4.8.10-x64-ubuntu-18.04/bin:$PATH' >> .bashrc

CMD bash



