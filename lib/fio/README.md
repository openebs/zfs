
This is a fio engine for zfs replica using replica network protocol to
configure data connections and issue IOs over them.

# Build

Use `--with-fio=DIR` in addition to `--enable-uzfs` configure option to
enable building it. `DIR` is a path to fio repository with fio include
files.

# Run

We assume that fio command is executed from the fio's repository directory.
In following command change path to zfs repository as appropriate:

```bash
LD_LIBRARY_PATH=/repos/zfs/lib/fio/.libs ./fio replica.fio
```

fio should get stuck and print a message `waiting for connection from replica`.
In another window start zfs replica and instruct it to connect to "fio
target" which is listening on loopback interface:

```bash
sudo /repos/zfs/cmd/zrepl/zrepl 127.0.0.1
```

At most after 5 secs `zrepl` will connect to fio and IO will start flowing.
`address` and `port` replica fio engine configuration options can be used
to avoid the listening phase and create data connection directly from fio
engine to zfs replica.
