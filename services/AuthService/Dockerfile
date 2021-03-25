FROM alpine:3.12.4

RUN apk add --no-cache \ 
    openssl libunwind libc6-compat=1.1.24-r10 \
    libstdc++ libintl zlib nghttp2-libs

ENV DOTNET_SYSTEM_GLOBALIZATION_INVARIANT true

ARG USER_ID=3232
ARG GROUP_ID=5858

WORKDIR /app

RUN addgroup -S -g ${GROUP_ID} dotnetcoregroup \
 && adduser -D dotnetcoreuser -u ${USER_ID} -g dotnetcoreuser -G dotnetcoregroup -S /bin/sh -h /

COPY --chown=dotnetcoregroup:dotnetcoreuser /app/out ./

EXPOSE 8080

ENTRYPOINT ["./AuthService"]