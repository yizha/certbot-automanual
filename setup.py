from setuptools import setup
from setuptools import find_packages

install_requires = [
    'acme',
    'certbot',
    'zope.interface',
]

setup(
    name='certbot-external',
    description="An external plugin for Let's Encrypt client (certbot)",
    url='https://github.com/yizha/certbot-external',
    author="Yicha Ding",
    author_email='ding.rickcat@gmail.com',
    license='Apache License 2.0',
    install_requires=install_requires,
    packages=find_packages(),
    entry_points={
        'certbot.plugins': [
            'auth = certbot_external.external:Authenticator',
            'install = certbot_external.external:Installer',
        ],
    },
)
