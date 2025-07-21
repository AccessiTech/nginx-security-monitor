from setuptools import setup, find_packages

setup(
    name="nginx-security-monitor",
    version="0.1.0",
    author="AccessiTech",
    author_email="accessit3ch@gmail.com",
    description="A simple set of Python scripts to monitor NGINX logs, detect attack patterns, mitigate intrusion tactics, and trigger alerts through email and SMS.",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pyyaml>=6.0",
        "cryptography>=3.4.8",
        "psutil>=5.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=6.0.0",
            "pytest-mock>=3.10.0",
            "coverage>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
