
"""
Created by David M. Gaviria
Carnegie Mellon University, Host-Based Forensics 
April 14, 2024
"""


from datetime import datetime
from java import io
from java.lang import System
from java.lang import Class
from java.util.logging import Level
from java.sql import DriverManager




class MmssmsParser():
    parentModule = None 
    custom_header = None

    # initalizes parser object
    def __init__(self, parentModule, custom_header = None):
        self.parentModule = parentModule            # should be the ConversationExtractorModule object that called this function
        self.custom_header = custom_header            # custom header to display on conversation output
        
    # connect log with log of the parent module
    def log(self, level, msg):
        self.parentModule.log(level, msg)


    # TODO - function to identify contacts
    def contactIdentifier(self):
        pass


    """Parses text message database of Android phones, which should be located in mmssms.db.  Accepts path to file,
    and returns a list of 'conversation tuples' which each has the format (participant1, participant2, message list).  
    Each 'message' in the message list in turn is a tuple of the format (sender, receiver, timestamp, content). """
    def parse(self, db_path):
        extractedConversations = []  # should be a list of tuples with format: (sender, receiver, timestamp, message)

        self.log(Level.INFO, "Starting MmssmsParser --")

        # initalize db connection
        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            conn = DriverManager.getConnection("jdbc:sqlite:%s"  % db_path)
        except Exception as e:
            self.log(Level.SEVERE, "Unable to establish connection to %s\n\t%s" %(db_path, e))
            return None

        # find list of unique numbers in messages                  
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
        
        # find conversations related to unique pairs of participants
        for number in numbersList:
                foundMessages = []
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
                            sender = resultSet.getString('address')
                            receiver = "this_device"    #TODO: identify address of this device
                        else:
                            receiver = resultSet.getString('address')
                            sender = "this_device"      #TODO: identify address of this device
                        # identify timestamp
                        timestamp = int(resultSet.getString('date')) / 1000   # mmssms.db uses Unix epoch in milliseconds
                        utc_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                        # get content
                        content = resultSet.getString('body')
                        foundMessages.append((sender, receiver, utc_time, content))

                    # log data as a convo
                    if foundMessages != []:
                        extractedConversations.append((sender, receiver, foundMessages))

                except Exception as e:
                    self.log(Level.INFO, "Error with extracting message data from resultSet\n\t%s" % e)

        # return parser results
        if extractedConversations != []:
            return extractedConversations
        else:
            return None