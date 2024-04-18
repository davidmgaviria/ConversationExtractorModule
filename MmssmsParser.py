
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



class MmssmsParser():
    # global variables
    custom_header = "Text Messages (mmssms.db)"         # custom header to display on conversation output
    contact_dbName = "contacts2.db"                     # name of db where contacts can be found to conduct contact matching
    contactTable = None                                 # contact table thatwill be used
    

    def __init__(self, parentModule, assignedCase, dataSource):        
        self.parentModule = parentModule            # should be the ConversationExtractorModule object that called this function
        self.assignedCase = assignedCase            # should be the case object this parser is running in
        self.parentDataSource = dataSource          # should be the data source in which the file the parser is analyzing was found
        

    """Connect log with log of the parent module"""
    def log(self, level, msg):
        self.parentModule.log(level, msg)


    """ Generates a contact table to be used by the parser.  It scans the specified database 
    file of the parser and extracts all id - number combinations it finds, then builds the table."""
    def generateContactTable(self) -> bool:
        fileManager = self.assignedCase.getServices().getFileManager()

        # Find contact db in datasource and save it 
        file = fileManager.findFiles(self.dataSource, self.contact_dbName)[0]  # returns list of AbstractFile objects
        unqiue_filename = str(hash(self.dataSource.getName())) + "-" + str(file.name) 
        stored_dbPath = os.path.join(self.assignedCase.getTempDirectory(), unqiue_filename)
        ContentUtils.writeToFile(file, io.File(stored_dbPath))   
        self.log(Level.FINE, "Found: %s for contact matching" % unqiue_filename) 
    
        # initalize db connection
        Class.forName("org.sqlite.JDBC").newInstance()
        conn = DriverManager.getConnection("jdbc:sqlite:%s"  % stored_dbPath)
       
        # find numbers in contacts             
        statement = conn.createStatement()
        resultSet = statement.executeQuery("""
            SELECT DISTINCT number, name 
                FROM contact""")        # TODO: what table & fields
        
        #-- Convert numbers to dictionary
        if resultSet != None:
            while resultSet.next():
                name = resultSet.getString('name')
                id = resultSet.getString('number')
                self.contactTable[id] = name
        # indicate table empty if no results were found
        else:
            self.contactTable == dict()


    """ Attempts to match given id with the name of the contact in the contact table. Will first 
    generate contact table if it doesnt exist.  If there is an error with generation of the name 
    cant be found, returns None. """
    def contactMatching(self, id):
        # generate contact table if it doesnt exist
        if self.contactTable == None:
            try:
                self.generateContactTable()
            except Exception as e:
                self.log(Level.WARNING, "Unable to generate contact table for %s\n\t%s" % (self.contact_dbName, e))
                return None
        
        # try to match id with name
        try:
            return self.contactTable[id]
        except:
            self.log(Level.WARNING, "Error when trying to match %s to a name, from %s\n\t%s" % (id, self.contact_dbName, e))
            return None



    """Parses text message database of Android phones, which should be located in mmssms.db.  Accepts path to file,
    and returns a list of Conversation objects."""
    def parse(self, db_path):
        conversations = []
        self.log(Level.INFO, "Starting MmssmsParser --")

        #-- Find number of device owner
        # TODO:
        deviceOwner = Contact(id="this_device")

        #-- Initalize db connection
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            conn = DriverManager.getConnection("jdbc:sqlite:%s"  % db_path)
        except Exception as e:
            self.log(Level.SEVERE, "Unable to establish connection to %s\n\t%s" %(db_path, e))
            return None

        #-- Find list of unique numbers in message, then for each message extract conversation between it and primary contacct 
        # find unique numbers                
        try:
            statement = conn.createStatement()
            resultSet = statement.executeQuery("""
                SELECT DISTINCT address 
                    FROM sms""")
            numbersList = []   
            while resultSet.next() != False:
                numbersList.append(resultSet.getString("address"))
        except Exception as e:
            self.log(Level.WARNING, "Unable to query numbers from %s\n\t%s" % (db_path, e))
            return None
        
        # find conversations related to this number and the primary contact
        for number in numbersList:
            # create new contact & conversation for this number
            newContact = Contact(id=number, name=self.contactMatching(number))   #TODO: contact identification
            newConversation = Conversation(deviceOwner, newContact)

            # find all messages related to these two participants
            try:
                query = """SELECT * 
                    FROM sms 
                    WHERE address = ?
                    ORDER BY date"""                       # using 'date' instead of 'date_sent' since it seems more reliable, (although what if message didnt send)?
                statement = conn.prepareStatement(query)
                statement.setString(1, str(number))
                resultSet = statement.executeQuery()
            except Exception as e:
                # log error and move to next iteration
                self.log(Level.INFO, "Unable to query messages between this device and %s from %s\n\t%s" % (number, db_path, e))
                continue

            # parse throught found messages and extract useful data
            try:
                while resultSet.next() != False:
                    # identify recipients (type 1 indicates incoming message, type 2 indicates outgoig)
                    if resultSet.getString('type') == str(1):
                        sender = newContact
                        receiver = deviceOwner
                    else:
                        sender = deviceOwner 
                        receiver = newContact
                    # identify timestamp
                    timestamp = int(resultSet.getString('date')) / 1000   # mmssms.db uses Unix epoch in milliseconds
                    utc_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    # get content
                    content = resultSet.getString('body')
                    newMessage = Message(sender, receiver, utc_time, content)
                    newConversation.addMsg(newMessage)
                # add conversation when loop is over
                if newConversation.length() > 0:
                    conversations.append(newConversation) 
            except Exception as e:
                self.log(Level.INFO, "Error with extracting message data from resultSet\n\t%s" % e)

        #-- Return parser results
        if conversations != []:
            return conversations
        else:
            return None