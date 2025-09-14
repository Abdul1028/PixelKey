from setuptools import setup, find_packages

setup(
    name='PixelKey',
    version='0.1.0',
    author='Abdul Shaikh',
    author_email='rasoolas2003@gmail.com',
    description='AES-GCM encryption with key derivation from image pixels and nonce hiding in image region.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Abdul1028/PixelKey',
    packages=find_packages(),
    install_requires=[
        'Pillow>=10.3.0',
        'cryptography>=3.4',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'Topic :: Multimedia :: Graphics',
    ],
    python_requires='>=3.8',
)
