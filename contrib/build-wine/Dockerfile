FROM ubuntu:22.04
LABEL description="Dedicated to building Electrum Dash executables for Windows"

ENV LC_ALL=C.UTF-8 LANG=C.UTF-8

USER root
WORKDIR /root

RUN dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        wget git binutils-mingw-w64 gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64-posix \
        win-iconv-mingw-w64-dev \
        build-essential libtool autoconf automake \
        gnupg2 \
        dirmngr gettext locales \
        python3-software-properties \
        software-properties-common \
    && wget -O /etc/apt/keyrings/winehq-archive.key https://dl.winehq.org/wine-builds/winehq.key \
    && wget -NP /etc/apt/sources.list.d/ https://dl.winehq.org/wine-builds/ubuntu/dists/$(lsb_release -sc)/winehq-$(lsb_release -sc).sources \
    && apt-get update \
    && apt-get install -y --install-recommends winehq-stable \
        cabextract xauth xvfb ca-certificates zip unzip p7zip-full  \
    && wget https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks \
    && chmod +x winetricks && mv winetricks /usr/local/bin \
    && rm -rf /var/lib/apt/lists/*

ENV WINEPATH c:/git/cmd;c:/Python310;c:/Python310/Scripts
ENV WINEDEBUG -all

ENV PY_PATH https://python.org/ftp/python/3.10.11/
ENV PY64_FILE python-3.10.11-amd64.exe
ENV PY64_MD5 a55e9c1e6421c84a4bd8b4be41492f51

ENV LIBUSB_PATH https://github.com/libusb/libusb/releases/download/v1.0.24/
ENV LIBUSB_FILE libusb-1.0.24.7z
ENV LIBUSB_SHA 620cec4dbe4868202949294157da5adb75c9fbb4f04266146fc833eef85f90fb

ENV NSIS_FILE nsis-3.05-setup.exe
ENV NSIS_PATH https://downloads.sourceforge.net/project/nsis/NSIS%203/3.05/
ENV NSIS_SHA 1a3cc9401667547b9b9327a177b13485f7c59c2303d4b6183e7bc9e6c8d6bfdb

ENV PATH=$PATH:/opt/wine-stable/bin

ENV WINEPREFIX /root/.wine-64
ENV WINEARCH win64
ENV PYHOME $WINEPREFIX/drive_c/Python310

RUN echo 'download and install 64-bit Python/git/NSIS' \
    && wineboot -i && xvfb-run -a winetricks win10 \
    \
    && wget -nv ${PY_PATH}${PY64_FILE} \
    && echo "${PY64_MD5} ${PY64_FILE}" | md5sum -c - \
    && xvfb-run -a wine $PY64_FILE /quiet InstallAllUsers=1 \
        TargetDir=$PYHOME && rm $PY64_FILE \
    && wine python -m pip install -U pip \
    \
    && wget -nv ${LIBUSB_PATH}${LIBUSB_FILE} \
    && echo "${LIBUSB_SHA} ${LIBUSB_FILE}" | sha256sum -c - \
    && 7z x -olibusb $LIBUSB_FILE -aos && rm $LIBUSB_FILE  \
    && cp libusb/VS2019/MS32/dll/libusb-1.0.dll $PYHOME/ \
    \
    && wget -nv ${NSIS_PATH}${NSIS_FILE} \
    && echo "${NSIS_SHA} ${NSIS_FILE}" | sha256sum -c - \
    && wine $NSIS_FILE /S \
    \
    && cp libusb/VS2019/MS64/dll/libusb-1.0.dll $PYHOME/ && rm -rf libusb \
    \
    && wine $NSIS_FILE /S  && rm $NSIS_FILE \
    \
    && rm -rf /tmp/.wine-0
