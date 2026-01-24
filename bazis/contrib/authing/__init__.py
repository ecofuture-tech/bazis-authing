try:
    from importlib.metadata import PackageNotFoundError, version
    __version__ = version('bazis-authing')
except PackageNotFoundError:
    __version__ = 'dev'
