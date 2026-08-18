FROM golang:1.23-bookworm AS build
RUN git clone --depth 1 https://github.com/Hackmanit/TInjA.git /src
WORKDIR /src
RUN go build -o /out/tinja .

FROM debian:bookworm-slim
# TInjA's --csti mode drives a headless Chromium through rod, so the browser libraries have to be
# present even though the default scan does not start one. Without them --csti fails at launch
# rather than at build, and client-side template injection is the one thing TInjA uniquely finds.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium \
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/tinja /usr/local/bin/tinja
ENV ROD_BROWSER_BIN=/usr/bin/chromium
RUN tinja --help > /dev/null
ENTRYPOINT ["tinja"]
