# Conversation Identifier & Extractor - Autopsy Plugin

This Autopsy plugin facilitates the viewing of text messages found on Android device images. It parses the `mmssms.db` file, matches messages by common participants, and orders them by timestamp. The result is output as a conversation transcript in an Autopsy report.

### Installation

1. Download the source code.
2. Place it in the `python_modules` folder in Autopsy.
3. Open Autopsy and navigate to **Generate Report**. The **Conversation Identifier & Extractor** report will be available for selection. Running this report generates the conversation transcript.

For more information on Autopsy, visit the [Autopsy official website](https://www.sleuthkit.org/autopsy/).

### Features

- Parses SMS conversations from the `mmssms.db` file.
- Groups messages by participants.
- Orders messages by timestamp for an organized transcript.
