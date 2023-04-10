from sqlalchemy import inspect
from sqlalchemy.ext.declarative import as_declarative
from flask_sqlalchemy import SQLAlchemy


__all__ = ("get_base_model",)


def get_base_model(db: SQLAlchemy):

    @as_declarative()
    class Base:
        """
        Usage:
            class Model(Base, db.Model):
                pass

        """

        def _asdict(self):
            """
            object_as_dict = lambda r: {c.name: str(getattr(r, c.name)) for c in r.__table__.columns}
            https://riptutorial.com/sqlalchemy/example/6614/converting-a-query-result-to-dict
            """
            return {c.key: getattr(self, c.key)
                    for c in inspect(self).mapper.column_attrs}

        @classmethod
        def get(cls, **kwargs):
            return cls.query.filter_by(**kwargs).first()

        @classmethod
        def get_or_create(cls, defaults=None, **kwargs):
            """
            A convenience method for looking up an object with the given kwargs,
            creating one if necessary.
            """
            created = False
            obj = cls.get(**kwargs)
            if not obj:
                obj = cls(**kwargs, **defaults)
                db.session.add(obj)  # insert the user
                db.session.commit()  # generate the auth token
                created = True
            return obj, created

        def save(self):
            db.session.add(self)
            db.session.commit()
            return self

        @staticmethod
        def rollback():
            db.session.rollback()

        @staticmethod
        def commit():
            db.session.commit()

    return Base

