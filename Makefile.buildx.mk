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

# IMAGE_ORG can be used to customize the organization 
# under which images should be pushed. 
# By default the organization name is `openebs`. 

ifeq (${IMAGE_ORG}, )
  IMAGE_ORG = openebs
  export IMAGE_ORG
endif

# Specify the date of build
DBUILD_DATE=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Specify the docker arg for repository url
ifeq (${DBUILD_REPO_URL}, )
  DBUILD_REPO_URL="https://github.com/openebs/upgrade"
  export DBUILD_REPO_URL
endif

# Specify the docker arg for website url
ifeq (${DBUILD_SITE_URL}, )
  DBUILD_SITE_URL="https://openebs.io"
  export DBUILD_SITE_URL
endif

# ==============================================================================
# Build Options

export DBUILD_ARGS=--build-arg DBUILD_DATE=${DBUILD_DATE} --build-arg DBUILD_REPO_URL=${DBUILD_REPO_URL} --build-arg DBUILD_SITE_URL=${DBUILD_SITE_URL}

ifeq (${TAG}, )
  export TAG=ci
endif


# Build cstor-base & cstor docker image with buildx
# Experimental docker feature to build cross platform multi-architecture docker images
# https://docs.docker.com/buildx/working-with-buildx/

# default list of platforms for which multiarch image is built
ifeq (${PLATFORMS}, )
	export PLATFORMS="linux/amd64,linux/arm64,linux/ppc64le"
endif

# if IMG_RESULT is unspecified, by default the image will be pushed to registry
ifeq (${IMG_RESULT}, load)
	export PUSH_ARG="--load"
    # if load is specified, image will be built only for the build machine architecture.
    export PLATFORMS="local"
else ifeq (${IMG_RESULT}, cache)
	# if cache is specified, image will only be available in the build cache, it won't be pushed or loaded
	# therefore no PUSH_ARG will be specified
else
	export PUSH_ARG="--push"
endif

# Name of the multiarch image for cstor-base
DOCKERX_IMAGE_CSTOR_BASE:=${IMAGE_ORG}/cstor-base:${TAG}

# Name of the multiarch image for cstor
DOCKERX_IMAGE_CSTOR:=${IMAGE_ORG}/cstor:${TAG}

# COMPONENT names for image builds
CSTOR_BASE:=cstor-base
CSTOR:=cstor

.PHONY: docker.buildx
docker.buildx:
	export DOCKER_CLI_EXPERIMENTAL=enabled
	@if ! docker buildx ls | grep -q container-builder; then\
		docker buildx create --platform ${PLATFORMS} --name container-builder --use;\
	fi
	@docker buildx build --platform ${PLATFORMS} \
		-t "$(DOCKERX_IMAGE_NAME)" ${DBUILD_ARGS} -f $(PWD)/docker/$(COMPONENT).Dockerfile \
		. ${PUSH_ARG}
	@echo "--> Build docker image: $(DOCKERX_IMAGE_NAME)"
	@echo

.PHONY: docker.buildx.cstor-base
docker.buildx.cstor-base: DOCKERX_IMAGE_NAME=$(DOCKERX_IMAGE_CSTOR_BASE)
docker.buildx.cstor-base: COMPONENT=$(CSTOR_BASE)
docker.buildx.cstor-base: docker.buildx

.PHONY: docker.buildx.cstor
docker.buildx.cstor: DOCKERX_IMAGE_NAME=$(DOCKERX_IMAGE_CSTOR)
docker.buildx.cstor: COMPONENT=$(CSTOR)
docker.buildx.cstor: docker.buildx

.PHONY: buildx.push.cstor-base
buildx.push.cstor-base:
	BUILDX=true DIMAGE=${IMAGE_ORG}/cstor-base ./build/push

.PHONY: buildx.push.cstor
buildx.push.cstor:
	BUILDX=true DIMAGE=${IMAGE_ORG}/cstor ./build/push
