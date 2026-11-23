# The h2c mock backends and the HTTP/2 client of radix-h2: python3 and
# python3-h2 from the distribution, on the base image radix-h1 pins.
FROM ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-h2 && rm -rf /var/lib/apt/lists/*
