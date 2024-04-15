
"""
Created by David M. Gaviria
Carnegie Mellon University, Host-Based Forensics 
April 9, 2024

The skeleton of this code was taken from 'reportmodules.py' in
the Autopsy 'pythonExamples' folder, which is public domain and
free-to-use for modification.
"""



import os
import jarray
import inspect
from datetime import datetime
from java import io
from java.lang import System
from java.lang import Class
from java.util.logging import Level
from java.sql import DriverManager
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.report import GeneralReportModuleAdapter
from org.sleuthkit.autopsy.report.ReportProgressPanel import ReportStatus
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.datamodel import ContentUtils

# import parsers
import MmssmsParser





"""A report module that parses through the text messages database and matches messages that 
have the same two participants.  The messages between two participants are considered a 
'conversation' that is ordered by timestamp and outputted to produce a transcript of 
said conversation"""

class ConversationExtractorModule(GeneralReportModuleAdapter):
    moduleName = "Conversation Identifier & Extractor"

    _logger = None
    def log(self, level, msg):
        if self._logger == None:
            self._logger = Logger.getLogger(self.moduleName)
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def getName(self):
        return self.moduleName

    def getDescription(self):
        return "Parses through the text messages database and identifies conversations by matching messages with the same two participants and ordering them by timestamp--each found conversation is printed as a transcript."

    # TODO: Update this to reflect where the report file will be written to
    def getRelativeFilePath(self):
        return "testReport.txt"
    
    #TODO: contact matching
    def numberToName(self, number):
        # should try to find name and just return number otherwise
        return str(number)


    """convert messages of conversations from database into a transcript"""
    def convertToTranscript(self, extractedConversations, db_name, report):
        # Report header listing source
        report.write("========================================================================\n" + db_name + "\n========================================================================")
        # Iterate through each conversation
        for conversationData in extractedConversations:
            try:
                user1 = self.numberToName(conversationData[0])
                user2 = self.numberToName(conversationData[1])  
                messageList = conversationData[2]

                # print transcript
                txt = ("\n\n\n\n#----------------- CONVERSATION: %s to %s ------------------#" % (user1, user2))
                report.write(txt)
                previous_sender = None
                for ele in messageList:
                    # expected tuple format: (sender, receiver, timestamp, message)
                    log = ""
                    msg_sender = ele[0]
                    msg_timestamp = ele[2]
                    msg_content = ele[3]
                    # write new sender if needed
                    if msg_sender != previous_sender:  
                        log += ("\n\n" + self.numberToName(msg_sender) + "\t" + msg_timestamp) 
                    # write message
                    cleaned_msg = msg_content.replace("\n\n", "")
                    log += ("\n > " + cleaned_msg)
                    report.write(log)
                    previous_sender = msg_sender
            except Exception as e:
                errorMsg = ("Failed to transcribe conversation between %s and %s" % (user1, user2))
                self.log(Level.INFO, "%s in %s\n\t %s" % (errorMsg, db_name, e))
    


    #   See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, reportSettings, progressBar):
        # target databases to search for
        targets = ["mmssms.db"]

        self.log(Level.FINE, "\n\n---------------- Begin Conversation Extractor report ----------------")
        # Get case, datasource and filemanager, and logger
        currentCase = Case.getCurrentCase()
        dataSources = currentCase.getDataSources()
        fileManager = currentCase.getServices().getFileManager()

        # Create report file & log
        fileName = os.path.join(reportSettings.getReportDirectoryPath(),"testReport.txt")
        report = open(fileName, 'w')
        self.log(Level.FINE, "Created report %s" % fileName)

        # Configure progress bar
        progressBar.setIndeterminate(True)
        progressBar.start()

        # Find target dbs in all available data sources & parse
        for ds in dataSources:
            dsName = ds.getName()
            for target_name in targets:
                # Find specific target in datasource & save on disk
                try:
                    files = fileManager.findFiles(ds, target_name)  # returns list of AbstractFile objects

                    self.log(Level.INFO, "Num objects %s" % len(files))

                    file = files[0]
                    unqiue_filename = str(hash(ds.getName())) + "-" + str(file.name) 
                    stored_dbPath = os.path.join(currentCase.getTempDirectory(), unqiue_filename)
                    ContentUtils.writeToFile(file, io.File(stored_dbPath))        
                    self.log(Level.FINE, "Found: %s in %s, storing at %s" % (target_name, dsName, stored_dbPath))
                except Exception as e:
                    # log error and move to next target
                    self.log(Level.WARNING, "Error with finding and writing %s to disk\n\t %s" % (unqiue_filename, e))
                    continue
                    
                # Parse database using appropriate parser, all return same format
                if target_name == "mmssms.db":
                    self.log(Level.INFO, ("Utilizing mmssmsParser for %s" % target_name))
                    # extractedConversations = MmssmsParser.parse(stored_dbPath)
                    # header = "Text Messages (mmssms.db)"
                    msgParser = MmssmsParser.MmssmsParser(self, "Text Messages (mmssms.db)")
                    extractedConversations = msgParser.parse(stored_dbPath)
                    header = msgParser.custom_header
                else:
                    # log error and move to next target
                    self.log(Level.WARNING, "Could not find appropriate parser for %s, skipping" % unqiue_filename)
                    continue
                
                # Log conversations to report
                if extractedConversations != None:
                    self.log(Level.FINE, "Found %s conversations for %s" % (len(extractedConversations), unqiue_filename))
                    self.convertToTranscript(extractedConversations, header, report)
                    

        # Output report once all targets have been found and parsed
        report.close()
        currentCase.addReport(fileName, self.moduleName, "Extracted Conversations")
        progressBar.complete(ReportStatus.COMPLETE)


