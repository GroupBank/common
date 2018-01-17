from setuptools import setup, find_packages

setup(
    name='groupbank-crypto',
    version='0.1',
    description='Cryptography library used by the Group Bank application',
    url='https://github.com/GroupBank/crypto',
    license='GNU Affero General Public License v3.0',
    author='Ricardo Amendoeira, David Fialho',
    author_email='ricardo.amendoeira@ist.utl.pt, fialho.david@protonmail.com',

    packages=find_packages(),

    install_requires=[
        'bitcoin==1.1.42',
        'cryptography==2.0.3',
        'asn1crypto==0.22.0',
        'pycryptodome==3.4.7',
    ],

    extras_require={
        'test': [
            'pytest'
        ],
    },
)
