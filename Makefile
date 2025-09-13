MODULE_big = user_contact
OBJS = user_contact.o

EXTENSION = user_contact
DATA = user_contact--1.0.sql   # ← ensure this line is present

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
