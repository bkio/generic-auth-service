FROM alpine:3.8

RUN apk add --no-cache \ 
    openssl libunwind libc6-compat=1.1.19-r11 \
    libstdc++ libintl zlib nghttp2-libs

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT true

WORKDIR /app
COPY /app/out ./

EXPOSE 8080

ENTRYPOINT ["./AuthService"]