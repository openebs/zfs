![img](http://zfsonlinux.org/images/zfs-linux.png)

ZFS on Linux is an advanced file system and volume manager which was originally
developed for Solaris and is now maintained by the OpenZFS community.

[![codecov](https://codecov.io/gh/zfsonlinux/zfs/branch/master/graph/badge.svg)](https://codecov.io/gh/zfsonlinux/zfs)

# Official Resources
  * [Site](http://zfsonlinux.org)
  * [Wiki](https://github.com/zfsonlinux/zfs/wiki)
  * [Mailing lists](https://github.com/zfsonlinux/zfs/wiki/Mailing-Lists)
  * [OpenZFS site](http://open-zfs.org/)

# Installation
Full documentation for installing ZoL on your favorite Linux distribution can
be found at [our site](http://zfsonlinux.org/).

# Contribute & Develop
We have a separate document with [contribution guidelines](./.github/CONTRIBUTING.md).

# Building
In addition to standard dependencies of ZFS on Linux project following
packages need to be installed:

```bash
sudo apt-get install libaio-dev libgtest-dev cmake libjemalloc-dev libjson-c-dev
```

Google test framework library does not have a binary package so it needs to be compiled manually:
```bash
cd /usr/src/gtest
sudo cmake -DBUILD_SHARED_LIBS=ON CMakeLists.txt
sudo make

# copy or symlink libgtest.a and libgtest_main.a to your /usr/lib folder
sudo cp *.so /usr/lib
```

Special configure option `--enable-debug` should be used in order to create
zfs and zpool commands which don't call into the kernel using ioctls, but
instead call into uZFS process for serving "ioctls" using tcp connection.
Other than that the build steps are the same as for ZoL:

```bash
./autogen.sh
CFLAGS="-g -O0" ./configure --enable-debug --enable-uzfs=yes
make
```

Additional configure option `--with-fio=<path-to-fio-repo>` can be supplied
in case that fio engine for `zrepl` is wanted.

# Running it

This assumes that you have configured zfs with `--enable-uzfs=yes` option.
To try zpool and zfs commands, start `cmd/zrepl/zrepl` binary with `sudo` and
leave it running. Now zpool and zfs commands from cmd/ directory can be
run in usual way and they will act on running instance of `zrepl`.

# Testing performance

Standard IO benchmarking tool `fio` can be used with special engine for
`zrepl`. Make sure that uzfs was configured and built with fio engine.
If that is the case, then the fio can be started as follows (replace
`$UZFS_PATH` by path to built uzfs repository):

```bash
LD_LIBRARY_PATH=fio
LD_LIBRARY_PATH=$UZFS_PATH/lib/fio/.libs fio config.fio
```

Example of fio config file can be found in `lib/fio` directory.

# Docker image

A docker image with zrepl *for testing purpose* can be built as follows.
The privileged parameter when starting container is to enable process
tracing inside the container. The last command gets you a shell inside
the container which can be used for debugging, running zfs & zpool commands,
etc. Explanation of the two mounted volumes follows:

 * /dev: All devices from host are visible inside the container so we can create pools on arbitrary block device.
 * /tmp: This is a directory where core is dumped in case of a fatal failure. We make it persistent in order to preserve core dumps for later debugging.

```bash
sudo docker build -t my-cstor .
sudo mkdir /tmp/cstor
sudo docker run --privileged -it -v /dev:/dev -v /run/udev:/run/udev --mount source=cstortmp,target=/tmp my-cstor
sudo docker exec -it <container-id> /bin/bash
```

You could also run local image repo and upload the test image there:

```bash
sudo docker run -d -p 5000:5000 --restart=always --name registry registry:2
sudo docker build -t localhost:5000/my-cstor .
sudo docker push localhost:5000/my-cstor
```

# Troubleshooting

In order to print debug messages start zrepl with `-l debug` argument. If
running zrepl in container with standard entrypoint.sh script, set env
variable LOGLEVEL=debug. To do the same when running zrepl on k8s cluster
use patch command to insert the same env variable to pod definition.
Details differ based on how zrepl container was deployed on k8s cluster:

```bash
kubectl patch deployment cstor-deployment-name --patch "$(cat patch.yaml)"
```

where patch.yaml content is:
```
spec:
  template:
    spec:
      containers:
      - name: cstor-container-name
        env:
        - name: LOGLEVEL
          value: "debug"
```

# Caveats

Disk write cache must be disabled for any device not managed by linux
sd driver. Cache flush is not supported for other drivers than sd.

# Contributing

Make sure to run cstyle on your changes before you submit a pull request:

```bash
make cstyle
```

And assure that the tests are passing. For possible tests to run see .travis.yml
file in root directory. Here is an example of running a couple of available
tests:

```bash
cmd/ztest/ztest -V
tests/cbtest/gtest/test_uzfs
tests/cbtest/gtest/test_zrepl_prot
sudo tests/cbtest/script/test_uzfs.sh
```
