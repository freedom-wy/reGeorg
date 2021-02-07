log_conf = {
    "version": 1,
    "formatters": {
        "regeorg_info": {
            "format": "%(asctime)s - %(pathname)s - %(lineno)s - %(name)s - %(levelname)s - %(message)s"
            # "format": "%(asctime)s - %(message)s"
        },
        "regeorg_debug": {
            "format": "%(asctime)s - %(pathname)s - %(lineno)s - %(name)s - %(levelname)s - %(message)s"
        }
    },
    "filters": {},
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "regeorg_info",
            "level": "INFO"
        },
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "regeorg_debug",
            "filename": "regeorg.log",
            "level": "DEBUG",
            "maxBytes": 1024*1024,
            "backupCount": 3
        }
    },
    "loggers": {
        "": {
            "handlers": ["console", "file"],
            "level": "DEBUG",
            "propagate": False
        }
    }
}
