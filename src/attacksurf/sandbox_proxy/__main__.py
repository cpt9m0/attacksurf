"""Entry point: `python -m attacksurf.sandbox_proxy`."""

from pathlib import Path, PurePosixPath

from attacksurf.config import SandboxProxySettings
from attacksurf.sandbox_proxy.policy import SandboxPolicy, load_images
from attacksurf.sandbox_proxy.server import make_server


def main() -> None:
    settings = SandboxProxySettings()
    images, osv_image = load_images(Path(settings.sandbox_images_lock))
    policy = SandboxPolicy(
        images=images,
        runtimes=settings.allowed_runtimes,
        artifact_root=PurePosixPath(settings.sandbox_artifact_root),
        osv_image=osv_image,
    )
    make_server(
        settings.sandbox_proxy_host,
        settings.sandbox_proxy_port,
        policy,
        settings.sandbox_docker_socket,
    ).serve_forever()


if __name__ == "__main__":
    main()
