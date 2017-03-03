from pip.req import parse_requirements
from setuptools import setup
from setuptools import find_packages


setup(
    name='Flask-OAuthRes',
    version='0.1.0',
    description="OAuth Resource for Flask",
    author='Lukasz Marcin Podkalicki',
    author_email='lukasz.podkalicki@socialwifi.com',
    url='https://github.com/socialwifi/flask-oauthres',
    packages=find_packages(exclude=['tests', 'example']),
    install_requires=[str(ir.req) for ir in parse_requirements('base_requirements.txt', session=False)],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    license='BSD',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
