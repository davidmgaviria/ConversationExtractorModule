
"""
Created by David M. Gaviria
Carnegie Mellon University, Host-Based Forensics 
April 17, 2024
"""


class Contact():
    def __init__(self, id, name=None):
        self.id = id              # tne unique value (phone #, email, username, etc) that identifies this contact
        self.name = name          # the name used for the contact
    
    def __repr__(self):# -> str:
        return "<Contact [%s, %s]>" % (self.name, self.id)
    
    "Function attempts to get the name of the contact, if no name returns the id"
    def getNameOrIdentifier(self):# -> str:
        if self.name is None:
            return self.id
        else:
            return self.name

    "Returns name and id of contact"
    def getFullName(self):# -> str:
        if self.name == None:
            return "'%s' (%s)" % (self.name, self.id)
        else: 
            return "'Unknown User' (%s)" % self.id
            
        

class Message():
    def __init__(self, sender, receiver, date_sent, content):
        self.sender = sender            # should be a Contact object
        self.receiver = receiver        # should be a Contact object
        self.date_sent = date_sent      # expected in utc time
        self.content = content

    def __repr__(self):# -> str:
        return "<Message [Sender: %s, Receiver: %s, Date Sent: %s]>" % (self.sender, self.receiver, self.date_sent)



class Conversation():
    def __init__(self, person1, person2, messages=None):
        self.person1 = person1          # should be a Contact object
        self.person2 = person2          # should be a Contact object
        if messages is None:
            messages = []               # initialize messages as an empty list if not provided
        self.messages = messages        # should be a list of messages
        
    def __repr__(self):# -> str:
        return "<Conversation [Person 1: %s, Person 2: %s, Length: %s]>" % (self.person1, self.person2, len(self.messages))  

    "Accepts a message object and appends it to the end of messages list"
    def addMsg(self, msg):
        self.messages.append(msg)

    "Returns the number of messages in this conversation"
    def length(self):# -> int:
        return len(self.messages)