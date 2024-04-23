
"""
Created by David M. Gaviria
Carnegie Mellon University, Host-Based Forensics 
April 14, 2024
"""


import os
from datetime import datetime
from java import io
from java.lang import System
from java.lang import Class
from java.util.logging import Level
from java.sql import DriverManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from util import Contact
from util import Message
from util import Conversation



class FbMsgParser():
    # global variables
    custom_header = "Facebook Messages (threads_db2.db)"         # custom header to display on conversation output

    
    def __init__(self, parentModule, assignedCase, dataSource):        
        self.parentModule = parentModule            # should be the ConversationExtractorModule object that called this function
        self.assignedCase = assignedCase            # should be the case object this parser is running in
        self.parentDataSource = dataSource          # should be the data source in which the file the parser is analyzing was found
        

    """Connect log with log of the parent module"""
    def log(self, level, msg):
        self.parentModule.log(level, msg)


    """Parses text message database of Android phones, which should be located in mmssms.db.  Accepts path to file,
    and returns a list of Conversation objects."""
    def parse(self, db_path):
        conversations = []
        self.log(Level.INFO, "Starting Facebook Messanger Parser --")

        #-- Initalize db connection
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            conn = DriverManager.getConnection("jdbc:sqlite:%s" % db_path)
        except Exception as e:
            self.log(Level.SEVERE, "Unable to establish connection to %s\n\t%s" %(db_path, e))
            return None

        #-- Find all distinct thread keys - each thread key corresponds to messages between two participants
        try:
            statement = conn.createStatement()
            resultSet = statement.executeQuery("""
                SELECT DISTINCT thread_key 
                    FROM threads""")
            threadsList = []   
            while resultSet.next() != False:
                threadsList.append(resultSet.getString("thread_key"))
        except Exception as e:
            self.log(Level.WARNING, "Unable to query thread_keys from %s\n\t%s" % (db_path, e))
            return None
        
        #-- For each thread key, extract messages
        for thread_key in threadsList:
            contact1 = Contact(None)        # contacts shouldnt be empty but workaround for now
            contact2 = Contact(None)        # contacts shouldnt be empty but workaround for now
            newConversation = Conversation(contact1, contact2)  

            self.log(Level.INFO, "RETRIEVING DATA FOR -- %s" % thread_key)

            # find all messages related to these two participants
            try:
                query = """SELECT sender, text, timestamp_ms
                    FROM messages 
                    WHERE thread_key = ?
                    ORDER BY timestamp_ms"""                       
                statement = conn.prepareStatement(query)
                statement.setString(1, str(thread_key))
                resultSet = statement.executeQuery()
            except Exception as e:
                self.log(Level.INFO, "Unable to query messages from thread %s in %s\n\t%s" % (thread_key, db_path, e))
                continue

            # extract information from messages
            try:
                while resultSet.next() != False:
                    # get sender info
                    senderRawString = resultSet.getString(1)  # sender info is a dict, but must be retrieved first as a string
                    if senderRawString is None or senderRawString =='None':
                        continue
                    else:
                        senderRawString = senderRawString.replace('"', '')
                        temp = senderRawString.split(",")
                        fb_key = temp[0].split('user_key:')[1]  
                        fb_name = temp[1].split('name:')[1]
                    # create contacts if not done
                    if contact1.id == None:
                        contact1.id = fb_key 
                        contact1.name = fb_name
                    elif contact2.id == None and fb_key != contact1.id:
                        contact2.id = fb_key 
                        contact2.name = fb_name

                    # extract rest of message info
                    text = resultSet.getString("text")
                    timestamp = int(resultSet.getString('timestamp_ms')) / 1000     # thread_db2.db uses Unix epoch in milliseconds
                    utc_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

                    # dont add useless messages
                    if text is None or text == 'None' or text == '' or text == ' ': 
                        continue
                    else:
                        # match message with proper sender and add to conversation
                        if fb_key == contact1.id:
                            newMessage = Message(sender=contact1, receiver=None, date_sent=utc_time, content=text)  # receiver shouldnt be empty but whatever
                        else:
                            newMessage = Message(sender=contact2, receiver=None, date_sent=utc_time, content=text)  # receiver shouldnt be empty but whatever
                        self.log(Level.INFO, "NEW MESSAGE ADDED - %s" % newMessage)
                        newConversation.addMsg(newMessage)
                # add conversations to export list if it isnt empty
                if newConversation.length() > 0:
                    conversations.append(newConversation)

            except Exception as e:
                self.log(Level.INFO, "Error with extracting message data from resultSet\n\t%s" % e)
                continue

        #-- Return parser results
        if conversations != []:
            return conversations
        else:
            return None



        