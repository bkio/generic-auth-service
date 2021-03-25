FROM alpine:3.12.4

RUN apk add --no-cache \ 
    openssl libunwind libc6-compat=1.1.19-r11 \
    libstdc++ libintl zlib nghttp2-libs

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT true

WORKDIR /app

RUN addgroup -S dotnetcoregroup && \     
    adduser -S dotnetcoreuser USER dotnetcoreuser

COPY --chown=dotnetcoregroup:dotnetcoreuser /app/out ./

EXPOSE 8080

ENTRYPOINT ["./AuthService"]