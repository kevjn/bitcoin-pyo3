from setuptools import setup
from setuptools_rust import Binding, RustExtension

setup(
    name='bitcoin',
    version="1.0",
    rust_extensions=[RustExtension("bitcoin.bitcoin", binding=Binding.RustCPython)],
    # rust extensions are not zip safe, just like C-extensions.
    zip_safe=False,
)
