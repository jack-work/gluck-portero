import logging

PRIORITIES = (
    (logging.CRITICAL, 2),
    (logging.ERROR, 3),
    (logging.WARNING, 4),
    (logging.INFO, 6),
)


class JournalFormatter(logging.Formatter):
    def __init__(self):
        super().__init__("%(levelname)s %(message)s")

    def format(self, record):
        prio = next((p for level, p in PRIORITIES if record.levelno >= level), 7)
        return f"<{prio}>" + super().format(record)


def configure():
    handler = logging.StreamHandler()
    handler.setFormatter(JournalFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
