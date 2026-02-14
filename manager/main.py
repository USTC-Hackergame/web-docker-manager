import logging
import select
import socket
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
import db
import urllib.parse as urlparse
import os
import time
import tempfile
import hashlib
import random
import string
import threading
import json
import httpx
import subprocess
import itertools
import pathlib
import nacl.encoding
import nacl.signing


# https://github.com/python/cpython/blob/a3443c0e22a8623afe4c0518433b28afbc3a6df6/Lib/http/server.py#L577
_control_char_table = str.maketrans(
        {c: fr'\x{c:02x}' for c in itertools.chain(range(0x20), range(0x7f,0xa0))})
_control_char_table[ord('\\')] = r'\\'

def sanitize_log(message: str) -> str:
    return message.translate(_control_char_table)

class SafeLogFilter(logging.Filter):
    def filter(self, record):
        record.msg = sanitize_log(str(record.msg))
        return True

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s (L%(lineno)d)"))
handler.addFilter(SafeLogFilter())
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def getenv(envn, default=""):
    ret = os.environ.get(envn, default).strip()
    if ret == "":
        ret = default
    return ret


DOMAIN = os.environ["hackergame_domain"]

tmp_path = "/dev/shm/hackergame"
tmp_flag_path = "/dev/shm"
conn_interval = int(os.environ["hackergame_conn_interval"])
challenge_timeout = int(os.environ["hackergame_challenge_timeout"])
pids_limit = int(os.environ["hackergame_pids_limit"])
mem_limit = os.environ["hackergame_mem_limit"]
flag_path = os.environ["hackergame_flag_path"]
flag_rule = os.environ["hackergame_flag_rule"]
challenge_docker_name = os.environ["hackergame_challenge_docker_name"]
data_dir = os.environ["hackergame_data_dir"]
readonly = int(getenv("hackergame_readonly", "0"))
mount_points = getenv("hackergame_mount_points", "[]")
mount_points = eval(mount_points)
use_network = int(getenv("hackergame_use_network", "0"))
use_internal_network = int(getenv("hackergame_use_internal_network", "0"))
cpus = float(getenv("hackergame_cpus", "0.2"))
# disk_limit = getenv("hackergame_disk_limit", "4G")
HOST_PREFIX = os.environ["hackergame_host_prefix"]
CHAL_PATH = os.environ["hackergame_chal_path"]
stdlog = int(getenv("hackergame_stdout_log", "0"))
# useinit = int(getenv("hackergame_use_init", "1"))
external_proxy_port = int(getenv("hackergame_external_proxy_port", "0"))
rootless = int(getenv("hackergame_rootless", "0"))
# extra_flag directly appends to "docker create ..."
extra_flag = os.environ.get("hackergame_extra_flag", "")
# append_token adds "?token=xxxxx" to url
append_token = int(getenv("hackergame_append_token", "0"))


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    pass


pubkey = nacl.signing.VerifyKey(pathlib.Path('pubkey').read_text().strip(), encoder=nacl.encoding.HexEncoder)


def validate(token):
    try:
        return pubkey.verify(token.encode(), encoder=nacl.encoding.HexEncoder).decode()
    except Exception:
        return None


def get_header(lines, header):
    header = header.lower() + b":"
    for line in lines:
        if line.lower().startswith(header):
            return line.split(b":", 1)[1].strip()
    return None


def stop_docker(cid):
    dockerinfo = db.get_container_by_cid(cid)
    subdomain = dockerinfo["host"]
    uid = dockerinfo["uid"]
    if challenge_docker_name.endswith("-challenge"):
        name_prefix = challenge_docker_name[:-10]
    else:
        name_prefix = challenge_docker_name
    child_docker_name = f"{name_prefix}_u{uid}_{subdomain}"
    db.delete_container(cid)
    os.system(f"docker stop -t 3 {child_docker_name}")
    os.system(f"rm -rf /vol/sock/{subdomain}")


domain_charset = (string.digits + string.ascii_lowercase)[2:]


def start_docker(uid, token):
    flags = generate_flags(token)
    flag_files = generate_flag_files(flags)
    while True:
        subdomain = "".join([random.choice(domain_charset) for _ in range(8)])
        di = db.get_container_by_host(subdomain)
        if di is None:
            break
    result = db.create_container(uid, subdomain)
    if not result:
        return
    os.environ["hackergame_token_" + subdomain] = token
    os.environ["hackergame_host_" + subdomain] = HOST_PREFIX + subdomain + DOMAIN
    os.environ["hackergame_cid_" + subdomain] = subdomain
    cmd = (
        f"docker run --init --rm -d "
        f"--pids-limit {pids_limit} -m {mem_limit} --memory-swap {mem_limit} --cpus {cpus} "
        f"-e hackergame_token=$hackergame_token_{subdomain} "
        f"-e hackergame_host=$hackergame_host_{subdomain} "
        f"-e hackergame_cid=$hackergame_cid_{subdomain} "
    )
    if use_network:
        assert not use_internal_network
        cmd += "--network challenge "
    elif use_internal_network:
        cmd += "--network challenge_internal "
    else:
        cmd += "--network none "
    if readonly:
        cmd += "--read-only "
    if extra_flag:
        cmd += extra_flag + " "
    # cmd += f"--storage-opt size={disk_limit} "

    # new version docker-compose uses "-" instead of "_" in the image name, so we try both
    name_prefix = challenge_docker_name[:-10]

    child_docker_name = f"{name_prefix}_u{uid}_{subdomain}"
    cmd += f'--name "{child_docker_name}" '

    with open("/etc/hostname") as f:
        hostname = f.read().strip()
    with open("/proc/self/mountinfo") as f:
        for part in f.read().split("/"):
            if len(part) == 64 and part.startswith(hostname):
                docker_id = part
                break
        else:
            raise ValueError("Docker ID not found")
    if not rootless:
        prefix = f"/var/lib/docker/containers/{docker_id}/mounts/shm/"
    else:
        prefix = (
            f"/home/rootless/.local/share/docker/containers/{docker_id}/mounts/shm/"
        )
    for flag_path, fn in flag_files.items():
        flag_src_path = prefix + fn.split("/")[-1]
        cmd += f"-v {flag_src_path}:{flag_path}:ro "
    cmd += f"-v {data_dir}/vol/sock/{subdomain}:/sock "
    for fsrc, fdst in mount_points:
        cmd += f"-v {fsrc}:{fdst} "
    if external_proxy_port:
        cmd += f"-v {data_dir}/vol/gocat:/gocat:ro "
    cmd += challenge_docker_name
    logger.info(cmd)
    os.system("mkdir -p /vol/sock/" + subdomain)
    os.system("chmod 755 /vol/sock/" + subdomain)
    os.system(cmd)
    time.sleep(0.1)
    if stdlog:
        # setsid is used to detach "docker logs ..." from our Python server to init
        # so subprocess.run would not wait for docker logs here (which we don't want)
        # Use subprocess.Popen solely would bring zombies on your lawn...
        with open(f"/vol/logs/{child_docker_name}.log", "wb") as f:
            subprocess.run(
                ["setsid", "-f", "docker", "logs", "-f", child_docker_name], stdout=f, stderr=f
            )  # todo: use better way to redirect logs
        time.sleep(0.1)
    if external_proxy_port:
        # Set GOMAXPROCS to make sure it does not exceed pid limit
        # Also note that /sock is root-writable, so ALL CHALLENGE CONTAINERS SHALL NOT USE ROOT TO RUN!
        # And here we set umask 066 to avoid the log being readable by players.
        subprocess.run(
            [
                "docker", "exec", "--user", "root", "--env", "GOMAXPROCS=4", "-d", child_docker_name,
                "sh", "-c", f"umask 066 && /gocat tcp-to-unix --src 127.0.0.1:{external_proxy_port} --dst /sock/gocat.sock > /sock/gocat.log 2>&1"
            ]
        )
        time.sleep(0.1)


def generate_flags(token):
    functions = {}
    for method in "md5", "sha1", "sha256":

        def f(s, method=method):
            return getattr(hashlib, method)(s.encode()).hexdigest()

        functions[method] = f

    if flag_path:
        flag = eval(flag_rule, functions, {"token": token})
        if isinstance(flag, tuple):
            return dict(zip(flag_path.split(","), flag))
        else:
            return {flag_path: flag}
    else:
        return {}


def generate_flag_files(flags):
    flag_files = {}
    for flag_path, flag in flags.items():
        with tempfile.NamedTemporaryFile("w", delete=False, dir=tmp_flag_path) as f:
            f.write(flag + "\n")
            fn = f.name
        os.chmod(fn, 0o444)
        flag_files[flag_path] = fn
    return flag_files


redirectPage = open("redirect.html").read()


def construct_https_target_url(ghost, token, through_unix=False):
    if not through_unix:
        url = "https://" + HOST_PREFIX + ghost + DOMAIN + ":8443" + CHAL_PATH
    else:
        url = "http://" + HOST_PREFIX + ghost + DOMAIN + CHAL_PATH
    if append_token:
        url += "?token=" + urlparse.quote(token)
    return url


class HTTPReverseProxy(StreamRequestHandler):
    def handle(self):
        logger.info("Accepting connection from %s:%s" % self.client_address)
        cont = self.connection.recv(4096)
        if not b"\r\n" in cont:
            self.server.close_request(self.request)
            return
        headers = cont.split(b"\r\n")
        MethodLine = headers[0].split()
        if len(MethodLine) != 3:
            self.closeRequestWithInfo("Invalid HTTP request")
            return
        try:
            PATH = MethodLine[1].decode()
        except:
            self.closeRequestWithInfo("Invalid Path")
            logger.info("Invalid Path")
            return
        if not PATH.startswith("/"):
            self.closeRequestWithInfo("Invalid Path")
            return
        HOST = get_header(headers, b"host")
        if HOST is None:
            self.closeRequestWithInfo("Invalid Host")
            logger.info("No Host header")
            return
        try:
            HOST = HOST.decode("utf-8")
        except:
            self.closeRequestWithInfo("Invalid Host header")
            logger.info("Invalid Host header")
            return
        logger.info("Client Host:%s", HOST)
        logger.info("Client Path:%s", PATH)

        if not HOST.startswith(HOST_PREFIX):
            self.closeRequestWithInfo("Invalid Host")
            return

        try:
            subdomain = HOST.split(".")[0][len(HOST_PREFIX) :]
        except:
            self.closeRequestWithInfo("Invalid Host")
            return

        if PATH.startswith("/docker-manager/"):
            token = None
            uid = None
            try:
                token = PATH.split("?", 1)[1]
                token = urlparse.unquote(token)
                logger.info("Get Token:%s", token)
                uid = validate(token)
                logger.info("Get User:%s", str(uid))
            except:
                pass
            if PATH.startswith("/docker-manager/stop"):
                dockerinfo = db.get_container_by_host(subdomain)
                if dockerinfo != None:
                    stop_docker(dockerinfo["cid"])
                    self.closeRequestWithInfo("Stopped")
                    return
                if uid != None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo != None:
                        stop_docker(dockerinfo["cid"])
                        self.closeRequestWithInfo("Stopped")
                        return
            if PATH.startswith("/docker-manager/start"):
                if uid != None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo == None:
                        lasttime = db.get_last_time(uid)
                        if lasttime and time.time() - lasttime < conn_interval:
                            self.closeRequestWithInfo(
                                "Too frequent, please retry after %s"
                                % time.asctime(time.localtime(conn_interval + lasttime))
                            )
                            return
                        start_docker(uid, token)
                        dockerinfo = db.get_container_by_uid(uid)
                        ghost = dockerinfo["host"]
                        self.closeRequestWithInfo(
                            redirectPage.replace(
                                "DOCKERURL",
                                construct_https_target_url(ghost, token),
                            )
                        )
                        return
            if PATH.startswith("/docker-manager/status"):
                if uid != None:
                    dockerinfo = db.get_container_by_uid(uid)
                    if dockerinfo != None:
                        ghost = dockerinfo["host"]
                        obj = {
                            "status": 0,
                            "host": ghost,
                            "url": construct_https_target_url(ghost, token),
                        }
                        code = 502
                        uds = "/vol/sock/" + ghost + "/gocat.sock"
                        try:
                            transport = httpx.HTTPTransport(uds=uds)
                            client = httpx.Client(transport=transport)
                            r = client.get(
                                construct_https_target_url(
                                    ghost, token, through_unix=True
                                ),
                                timeout=1,
                                follow_redirects=False,
                            )
                            code = r.status_code
                        except Exception as e:
                            logger.exception("Connect to %s failed", uds)
                            code = 502
                        obj["code"] = code
                        self.closeRequestWithInfo(json.dumps(obj))
                        return
                    else:
                        self.closeRequestWithInfo(json.dumps({"status": -1}))
                        return
            dockerinfo = db.get_container_by_host(subdomain)
            if dockerinfo != None:
                ghost = dockerinfo["host"]
                self.closeRequestWithRedirect(
                    construct_https_target_url(ghost, token), "Redirecting"
                )
                return
            dockerinfo = db.get_container_by_uid(uid)
            if dockerinfo != None:
                ghost = dockerinfo["host"]
                self.closeRequestWithRedirect(
                    construct_https_target_url(ghost, token), "Redirecting"
                )
                return
            self.closeRequestWithInfo("Docker not found")
            return

        dockerinfo = db.get_container_by_host(subdomain)
        if dockerinfo == None:
            self.closeRequestWithInfo("Docker not found")
            return
        sock_path = "/vol/sock/" + dockerinfo["host"] + "/gocat.sock"
        # remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # remote.connect(('192.168.192.102',80))
        self.lasttime = int(time.time())
        self.cid = dockerinfo["cid"]
        db.update_container(self.cid)
        remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        remote.connect(sock_path)

        remote.sendall(cont)
        self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def closeRequestWithInfo(self, info):
        dat = (
            b"HTTP/1.1 200 OK\r\n"
            + b"Content-Type: text/html\r\n"
            + b"Connection: close\r\n"
            + b"\r\n"
            + info.encode()
        )
        self.request.sendall(dat)
        self.server.close_request(self.request)

    def closeRequestWithRedirect(self, url, info=""):
        dat = (
            b"HTTP/1.1 302 Moved Temporatily\r\n"
            + b"Location: "
            + url.encode()
            + b"\r\n"
            + b"Content-Type: text/html\r\n"
            + b"Connection: close\r\n"
            + b"\r\n"
            + info.encode()
        )
        self.request.sendall(dat)
        self.server.close_request(self.request)

    def exchange_loop(self, client, remote):
        while True:
            r, w, e = select.select([client, remote], [], [])
            if client in r:
                data = client.recv(4096)
                if len(data) > 0:
                    if time.time() - self.lasttime > challenge_timeout // 100:
                        db.update_container(self.cid)
                        self.lasttime = int(time.time())
                if remote.send(data) <= 0:
                    break
            if remote in r:
                data = remote.recv(4096)
                if len(data) > 0:
                    if time.time() - self.lasttime > challenge_timeout // 100:
                        db.update_container(self.cid)
                        self.lasttime = int(time.time())
                if client.send(data) <= 0:
                    break


def autoclean():
    while True:
        time.sleep(30)
        try:
            cons = db.get_all_containers()
            for x in cons:
                if int(time.time()) - x["last_time"] > challenge_timeout:
                    logger.info(
                        "Auto Clean:%s %s %s", x["cid"], x["uid"], x["host"]
                    )
                    stop_docker(x["cid"])
        except Exception as e:
            logger.exception("Auto clean failed")


def log_existing_docker():
    if stdlog:
        dockerinfo = db.get_all_containers()
        for x in dockerinfo:
            child_docker_name = f"{challenge_docker_name[:-10]}_u{x['uid']}_{x['host']}"
            # docker logs -f output logs from the very beginning...
            with open(f"/vol/logs/{child_docker_name}.log", "wb") as f:
                subprocess.run(
                    ["setsid", "-f", "docker", "logs", "-f", child_docker_name], stdout=f, stderr=f
                )


if __name__ == "__main__":
    # Modern docker compose uses -challenge, so we just change name here.
    if challenge_docker_name.endswith("_challenge"):
        challenge_docker_name = challenge_docker_name[:-10] + "-challenge"
    assert challenge_docker_name.endswith("-challenge")
    assert data_dir != ""
    if not os.path.exists("/vol/db"):
        os.mkdir("/vol/db")
        db.init_db()
    if not os.path.exists("/vol/sock"):
        os.mkdir("/vol/sock")
    if not os.path.exists("/vol/logs"):
        os.mkdir("/vol/logs")
    if external_proxy_port:
        # It could be the case when /vol/gocat is running
        # If checking system() return code here, it might report "Text file busy" error.
        os.system("cp /gocat /vol/gocat")
    log_existing_docker()
    threading.Thread(target=autoclean).start()
    with ThreadingTCPServer(("0.0.0.0", 8080), HTTPReverseProxy) as server:
        server.serve_forever()

# TODO: Auto cleanup
