FROM alpine:3.12.4

RUN apk add --no-cache \ 
    openssl libunwind libc6-compat=1.1.24-r10 \
    libstdc++ libintl zlib nghttp2-libs

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT true

WORKDIR /app

COPY /app/out ./

RUN chmod +x ./AuthService

EXPOSE 8080

ENTRYPOINT ["./AuthService"]