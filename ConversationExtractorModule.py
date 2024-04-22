
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
from util import Contact
from util import Message
from util import Conversation
from fpdf.fpdf import FPDF

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
    def convertToTranscript(self, extractedConversations, header, report):
        # Report header listing source
        report.write("========================================================================\n" + str(header) + "\n========================================================================")
        # Iterate through each conversation
        for convObj in extractedConversations:
            try:
                person1 = convObj.person1.getFullName()  
                person2 = convObj.person2.getFullName()                                            
                messages = convObj.messages

                # print transcript
                txt = ("\n\n\n\n#----------------- CONVERSATION: %s to %s ------------------#" % (person1, person2))
                report.write(txt)
                previous_sender = None
                for msgObj in messages:
                    # expected tuple format: (sender, receiver, timestamp, message)
                    log = ""
                    msg_sender = msgObj.sender.getNameOrIdentifier()         
                    msg_date_sent = msgObj.date_sent
                    msg_content = msgObj.content
                    # write new sender if needed
                    if msg_sender != previous_sender:  
                        log += ("\n\n" + self.numberToName(msg_sender) + "\t" + msg_date_sent) 
                    # write message
                    cleaned_msg = msg_content.replace("\n\n", "")
                    log += ("\n > " + cleaned_msg)
                    report.write(log)
                    previous_sender = msg_sender
            except Exception as e:
                errorMsg = ("Failed to transcribe conversation between %s and %s" % (person1, person2))
                self.log(Level.INFO, "%s in %s\n\t %s" % (errorMsg, header, e))
    


    #   See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1report_1_1_report_progress_panel.html
    def generateReport(self, reportSettings, progressBar):
        # target databases to search for
        targets = ["mmssms.db"]

        self.log(Level.FINE, "\n\n---------------- Begin Conversation Extractor report ----------------")
        # Get case, datasource and filemanager, and logger
        currentCase = Case.getCurrentCase()
        dataSourceList = currentCase.getDataSources()
        fileManager = currentCase.getServices().getFileManager()

        # Create report file & log
        fileName = os.path.join(reportSettings.getReportDirectoryPath(),"testReport.txt")
        report = open(fileName, 'w')
        self.log(Level.FINE, "Created report %s" % fileName)

        # Configure progress bar
        progressBar.setIndeterminate(True)
        progressBar.start()

        # Find target dbs in all available data sources & parse
        for dataSource in dataSourceList:
            ds_name = dataSource.getName()
            for target_name in targets:
                # Find specific target in datasource & save on disk
                try:
                    file = fileManager.findFiles(dataSource, target_name)[0]  # return first AbstractFile objects
                    unqiue_filename = str(hash(ds_name)) + "-" + str(file.name) 
                    stored_dbPath = os.path.join(currentCase.getTempDirectory(), unqiue_filename)
                    ContentUtils.writeToFile(file, io.File(stored_dbPath))        
                    self.log(Level.FINE, "Found: %s in %s, storing at %s" % (target_name, ds_name, stored_dbPath))
                except Exception as e:
                    # log error and move to next target
                    self.log(Level.WARNING, "Error with finding and writing %s to disk\n\t %s" % (unqiue_filename, e))
                    continue
                    
                # Parse database using appropriate parser, all return same format
                if target_name == "mmssms.db":
                    self.log(Level.INFO, ("Utilizing mmssmsParser for %s" % target_name))
                    msgParser = MmssmsParser.MmssmsParser(self, currentCase, dataSource)
                    extractedConversations = msgParser.parse(stored_dbPath)
                    header = msgParser.custom_header
                else:
                    # log error and move to next target
                    self.log(Level.WARNING, "Could not find appropriate parser for %s, skipping" % unqiue_filename)
                    continue
                
                # self.log(Level.INFO, "# of convos: %s" % len(extractedConversations))
                # for convo in extractedConversations:
                #     self.log(Level.INFO, "\t> %s" % convo)

                # Log conversations to report
                if extractedConversations != None:
                    self.log(Level.FINE, "Found %s conversations for %s" % (len(extractedConversations), unqiue_filename))
                    self.convertToTranscript(extractedConversations, header, report)
                    

        # Output report once all targets have been found and parsed
        report.close()
        currentCase.addReport(fileName, self.moduleName, "Extracted Conversations")
        progressBar.complete(ReportStatus.COMPLETE)


