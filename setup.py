from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read production requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#") and not line.startswith("-r")]

# Read development requirements  
with open("requirements-dev.txt", "r", encoding="utf-8") as fh:
    dev_requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#") and not line.startswith("-r")]

setup(
    name="ktscan",
    version="0.1.0",
    author="Kouki Security",
    author_email="admin@koukisec.org",
    description="A multi-threaded SSL/TLS certificate scanner and compliance tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/koukisecurity/ktscan",
    packages=find_packages(exclude=["tests*"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="ssl, tls, certificate, security, validation, scanning, x509, cryptography",
    python_requires=">=3.10",  # Updated due to truststore dependency
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0", 
            "pytest-mock>=3.10.0",
            "pytest-asyncio>=0.21.0",
            "freezegun>=1.2.0",
            "responses>=0.23.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ktscan=ktscan.cli:cli",
        ],
    },
    project_urls={
        "Bug Reports": "https://github.com/koukisecurity/ktscan/issues",
        "Source": "https://github.com/koukisecurity/ktscan",
        "Documentation": "https://github.com/koukisecurity/ktscan/blob/main/README.md",
    },
)