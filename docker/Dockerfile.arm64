#
# This Dockerfile builds cstor main container running zrepl from base image
#

FROM openebs/cstor-base-arm64:ci

COPY entrypoint-poolimage.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/entrypoint-poolimage.sh

ARG BUILD_DATE
LABEL org.label-schema.name="cstor"
LABEL org.label-schema.description="OpenEBS cStor"
LABEL org.label-schema.url="http://www.openebs.io/"
LABEL org.label-schema.vcs-url="https://github.com/openebs/openebs"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$BUILD_DATE

ENTRYPOINT entrypoint-poolimage.sh
EXPOSE 7676
