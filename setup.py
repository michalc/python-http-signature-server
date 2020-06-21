import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='http-signature-server',
    version='0.0.6',
    author='Michal Charemza',
    author_email='michal@charemza.name',
    description='Implementation of the server side of the IETF draft "Signing HTTP Messages"',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/michalc/python-http-signature-server',
    py_modules=[
        'http_signature_server',
    ],
    python_requires='>=3.6.3',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security :: Cryptography',
    ],
)
