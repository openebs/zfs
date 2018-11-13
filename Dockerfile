#
# This Dockerfile builds a recent base image containing cstor binaries and 
# libraries.
#

FROM ubuntu:16.04

RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \ 
    apt-get update && \
    apt-get install -y apt-utils libaio1 libjemalloc1

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

COPY cmd/zrepl/.libs/zrepl /usr/local/bin/
COPY cmd/zpool/.libs/zpool /usr/local/bin/
COPY cmd/zfs/.libs/zfs /usr/local/bin/
COPY cmd/zstreamdump/.libs/zstreamdump /usr/local/bin/

COPY lib/libzrepl/.libs/*.so* /usr/lib/
COPY lib/libzpool/.libs/*.so* /usr/lib/
COPY lib/libuutil/.libs/*.so* /usr/lib/
COPY lib/libnvpair/.libs/*.so* /usr/lib/
COPY lib/libzfs/.libs/*.so* /usr/lib/
COPY lib/libzfs_core/.libs/*.so* /usr/lib/

ARG BUILD_DATE
LABEL org.label-schema.name="cstor"
LABEL org.label-schema.description="OpenEBS cstor"
LABEL org.label-schema.url="http://www.openebs.io/"
LABEL org.label-schema.vcs-url="https://github.com/openebs/cstor"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
EXPOSE 7676
