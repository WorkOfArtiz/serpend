from distutils.core import setup, Extension

module = Extension('lookup3',
                    define_macros = [('MAJOR_VERSION', '1'), ('MINOR_VERSION', '0')],
                    include_dirs = ['lib/'],
                    sources = ['lib/lookup3.c', 'src/python-lookup3-module.c'])

setup (name = 'serpend',
       version = '0.1',
       description = 'Python bindings for the systemd hashing function with lookup3',
       author = 'Arthur de Fluiter',
       author_email = 'arghhhhthur@gmail.com',
       url = 'https://github.com/WorkOfArtiz/serpend',
       long_description = 'systemd journals analysis tool',
       ext_modules = [module]
)