from datetime import datetime


class Chat:

    def __init__(self):
        self.messages = {}
        self.date_created = datetime.now()

    def to_dict(self):
        """Convert the object to a dictionary for MongoDB storage."""
        return {
            "date_created": self.date_created.isoformat(),
            "messages": self.messages,
        }


class P2PChat(Chat):
    def __init__(self, name1, name2):
        super().__init__()
        self.name1 = name1
        self.name2 = name2

    def to_dict(self):
        """Extend the dictionary representation from the parent class."""
        p2p_dict = super().to_dict()
        p2p_dict.update({
            "user1": self.name1,
            "user2": self.name2
        })
        return p2p_dict


class Group(Chat):
    def __init__(self, name, admin, starting_members):
        super().__init__()
        self.name = name
        self.admin = admin
        self.members = starting_members

    def to_dict(self):
        """Extend the dictionary representation from the parent class."""
        group_dict = super().to_dict()
        group_dict.update({
            "name": self.name,
            "admin": self.admin,
            "members": self.members,
        })
        return group_dict


