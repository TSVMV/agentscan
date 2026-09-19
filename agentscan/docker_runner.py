"""Docker 目标启动器。

用法：agentscan scan --docker-image <image> --docker-port <容器内端口> ...
流程：docker run -d -p 随机端口:容器端口 -> 轮询等待目标响应 -> 扫描 -> docker rm -f 清理。

注意：启动的是用户自己提供的镜像（用户对该镜像内容负责），
AgentScan 只负责启动、等待、清理，不注入任何虚拟数据。
"""

import socket
import subprocess
import time
from typing import List, Optional

import requests


class DockerError(Exception):
    pass


def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _docker(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker"] + args, capture_output=True, text=True, timeout=timeout)


def start(image: str, container_port: int, extra_args: Optional[List[str]] = None,
          host_port: Optional[int] = None, wait_timeout: int = 240) -> dict:
    """启动目标容器并等待端口可访问。返回 {container_id, host_port, url}。"""
    if not docker_available():
        raise DockerError("本机未检测到可用的 docker 命令，无法使用 --docker-image（可直接用 --url 连接已启动的容器）")
    extra_args = extra_args or []
    host_port = host_port or _free_port()
    cmd = ["run", "-d", "--rm", "-p", f"{host_port}:{container_port}"] + extra_args + [image]
    r = _docker(cmd, timeout=300)
    if r.returncode != 0:
        raise DockerError(f"docker run 失败:\n{r.stderr.strip()}")
    container_id = r.stdout.strip()

    url = f"http://127.0.0.1:{host_port}"
    deadline = time.time() + wait_timeout
    last_err = ""
    while time.time() < deadline:
        try:
            requests.get(url, timeout=3)
            return {"container_id": container_id, "host_port": host_port, "url": url}
        except requests.ConnectionError:
            last_err = "连接被拒绝（服务可能仍在启动）"
        except requests.Timeout:
            last_err = "连接超时（端口已开但服务未响应）"
        # 容器若已退出则立即失败，不再空等
        ps = _docker(["ps", "-f", f"id={container_id}", "--format", "{{.Status}}"])
        if ps.returncode == 0 and container_id[:12] not in ps.stdout:
            logs = container_logs(container_id)
            raise DockerError(f"容器在启动后退出。docker logs:\n{logs}")
        time.sleep(2)
    stop(container_id)
    raise DockerError(f"等待 {wait_timeout}s 后目标仍未响应（{last_err}）。容器已清理。")


def stop(container_id: str) -> None:
    try:
        _docker(["rm", "-f", container_id], timeout=60)
    except Exception:
        pass


def container_logs(container_id: str) -> str:
    try:
        r = _docker(["logs", "--tail", "50", container_id], timeout=30)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return "(无法获取容器日志)"
