# Zeek plus the pinned CISA ICSNPP S7comm plugin with Substation's reviewed
# bounds patch, for complete Tier-2 verification in Docker.
#
# Built by `python scripts/verify/build_s7.py --docker` (and automatically by
# `make verify`). That helper verifies the upstream commit, applies the patch on
# the host and passes the prepared tree as the only build context, so this build
# fetches no source code. Only the compiler toolchain comes from Debian packages;
# it stays in the build stage.
ARG ZEEK_IMAGE

FROM ${ZEEK_IMAGE} AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake g++ make \
 && rm -rf /var/lib/apt/lists/*
COPY source /src
RUN cmake -S /src -B /build -DCMAKE_MODULE_PATH="$(zeek-config --cmake_dir)" \
 && cmake --build /build --parallel "$(nproc)" \
 && cmake --install /build

FROM ${ZEEK_IMAGE}
COPY --from=build /usr/local/zeek/lib/zeek/plugins/ /usr/local/zeek/lib/zeek/plugins/
