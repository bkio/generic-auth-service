FROM alpine:3.12.4

RUN apk add --no-cache \ 
    openssl libunwind libc6-compat=1.1.24-r10 \
    libstdc++ libintl zlib nghttp2-libs

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT true

WORKDIR /app

RUN addgroup -S -g 5858 dotnetcoregroup \
 && adduser -D dotnetcoreuser -u 3232 -g dotnetcoreuser -G dotnetcoregroup -S /bin/sh -h /

COPY --chown=dotnetcoregroup:dotnetcoreuser /app/out ./

EXPOSE 8080

ENTRYPOINT ["./AuthService"]