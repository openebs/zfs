# Copyright 2020 The OpenEBS Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM ubuntu:18.04 as build

RUN mkdir -p cstor
COPY . cstor/

# Final
FROM openebs/cstor-base:ci

COPY --from=build cstor/docker/entrypoint-poolimage.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/entrypoint-poolimage.sh

ARG DBUILD_DATE
ARG DBUILD_REPO_URL
ARG DBUILD_SITE_URL

LABEL org.label-schema.name="cstor"
LABEL org.label-schema.description="OpenEBS cStor"
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.build-date=$DBUILD_DATE
LABEL org.label-schema.vcs-url=$DBUILD_REPO_URL
LABEL org.label-schema.url=$DBUILD_SITE_URL

ENTRYPOINT entrypoint-poolimage.sh
EXPOSE 7676
