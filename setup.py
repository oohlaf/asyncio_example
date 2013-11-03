import os
import re

from setuptools import setup, find_packages


here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()
CHANGES = open(os.path.join(here, 'CHANGES.rst')).read()

fp_init = open(os.path.join(here, 'asyncio_example', '__init__.py'))
VERSION = re.compile(r".*__version__ = '(.*?)'",
                     re.S).match(fp_init.read()).group(1)
fp_init.close()


requires = ['asyncio',
            'aiohttp',
            ]


tests_require = ['nose',
                 'coverage',
                 ]


setup(name='asyncio_example',
      version=VERSION,
      description='',
      long_description=README + '\n\n' + CHANGES,
      classifiers=["Programming Language :: Python :: 3.3",
                   "Programming Language :: Python :: 3.4",
                   "Topic :: Internet :: WWW/HTTP",
                   ],
      author='Olaf Conradi',
      author_email='olaf@conradi.org',
      keywords='',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=requires,
      tests_require=tests_require,
      test_suite="asyncio_example",
      )
