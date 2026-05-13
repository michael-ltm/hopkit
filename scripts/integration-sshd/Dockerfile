FROM linuxserver/openssh-server:latest

ENV PUID=1000 PGID=1000 TZ=UTC \
    USER_NAME=tester \
    SUDO_ACCESS=true \
    PASSWORD_ACCESS=false \
    PUBLIC_KEY_FILE=/keys/test.pub

EXPOSE 2222
