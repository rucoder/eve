FROM lfedge/eve-alpine:ab798ccee75f48f5a3be7027f70dc5f63843ddde AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
