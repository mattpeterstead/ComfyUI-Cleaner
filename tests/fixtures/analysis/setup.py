from setuptools import setup

INSTALL_REQUIRES = ["setup-runtime>=1"]

setup(
    install_requires=INSTALL_REQUIRES,
    extras_require={"extra": ["setup-extra>=1"]},
)
