# Local example

Applies circuit-trufflehog to a throwaway Rocky Linux 10 container with systemd, with a daily scan of `/etc`, `/home`, `/root`, `/opt` and `/srv` that leaves out the container's SSH host keys and checks nothing against the internet. You need Conn3x and Podman.

```sh
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` The apply sets up the daily timer but doesn't scan. To run a scan now and see the counts:

```sh
ssh -p 2222 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'systemctl start conn3x-trufflehog.service; cat /var/lib/conn3x-trufflehog/latest/summary.txt'
```

A fresh container has nothing to find, so the summary is empty. Want to watch it catch something? `check.sh` plants the placeholder Slack webhook from Slack's documentation under `/opt`, scans, and checks the findings name it and leave out the host keys. It also checks the scan wrote nothing outside its results directory, then removes the plant:

```sh
podman exec -i circuit-trufflehog sh < check.sh
```

`up.sh` listens on `127.0.0.1:2222`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINER_NAME` to name the container something else. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On a Mac, rootful Podman is simplest: `export CONTAINER_CONNECTION=podman-machine-default-root`.

Podman doesn't give the container `CAP_DAC_READ_SEARCH`, so the scan logs files such as `/etc/shadow` as unreadable here. On a real host it reads them. See the main README.

`./down.sh` removes the container, its volumes, the key and the state.
