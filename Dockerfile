FROM debian:stretch-slim

RUN apt-get update
RUN apt-get install -y wget gnupg apt-transport-https pkg-config

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN echo 'deb http://apt.llvm.org/stretch/ llvm-toolchain-stretch-8 main\ndeb-src http://apt.llvm.org/stretch/ llvm-toolchain-stretch-8 main\n' > /etc/apt/sources.list.d/llvm.list
RUN apt-get update
RUN apt install -y cmake build-essential clang-8 clang-format-8 libfuzzer-8-dev clang-tools-8 libssl-dev git

CMD ["/bin/bash", "/home/github/picoquic/build.sh"]