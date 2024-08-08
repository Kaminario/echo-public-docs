import os

from setuptools import find_packages, setup

loc = os.path.abspath(os.path.dirname(__file__))

setup(
    name="silk-server",
    version="0.1.0",
    description="Silk echo server for Instant Extract Instrumentation",
    author="Ilya Levin",
    author_email="ilya.levin@silk.us",
    url="https://github.com/Kaminario/instant-extract-instrumentation",
    packages=find_packages(),
    install_requires=(
        "pydantic == 2.8",
        "fastapi == 0.112.0",
        "uvicorn == 0.30.5",
        "requests == 2.32.3",  # for client
    ),
    entry_points={"console_scripts": ("start-silk-server=server.server:main",)},
)
