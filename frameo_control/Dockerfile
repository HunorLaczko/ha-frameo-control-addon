# https://developers.home-assistant.io/docs/add-ons/configuration#add-on-dockerfile
ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install system dependencies (libusb for ADB over USB)
RUN apk add --no-cache libusb-dev build-base

# Copy root filesystem into the container
COPY rootfs/ /

# Make all shell scripts in the init and services directories executable
RUN find /etc/cont-init.d/ -type f -exec chmod +x {} \;
RUN find /etc/services.d/ -type f -exec chmod +x {} \;