#!/usr/bin/env python3
from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

setup(
    name="nonoise",
    version="0.1.0",
    author="Sh4d0w",
    author_email="your.email@example.com",  # Update this
    description="A passive-first reconnaissance tool focused on signal, not noise",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/nonoise",  # Update this
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "urllib3>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "nonoise=nonoise.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "nonoise": ["../wordlists/*.txt"],
    },
    zip_safe=False,
)
