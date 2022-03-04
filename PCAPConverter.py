#!/usr/bin/env python3

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PCAPToXLSX import *
    import time
    import sys
    import os
except Exception as e:
    print("[!] Library import error: %s " % e)

class Window(QWidget):

    def __init__(self):
        #
        QWidget.__init__(self)
        QLabel.__init__(self)
        #
        self.setWindowTitle('PCAP Converter')
        self.setGeometry(850,400,300,300)
        #
        self.upload_button = QPushButton("Upload PCAP File", self)
        self.upload_button.clicked.connect(self.GetFile)
        #
        self.parse_button = QPushButton("Convert PCAP", self)
        #
        self.format_label      = QLabel("Format")
        self.format_combo_box  = QComboBox()
        self.format_combo_box.addItem('CSV')
        self.format_combo_box.addItem('XLSX')
        self.format_combo_box.addItem('TXT')
        #
        self.status_label      = QLabel("Status: Ready")
        self.status_label.setStyleSheet("background-color: cyan")
        #
        main_layout              = QFormLayout()
        self.vertical_button_box = QVBoxLayout()
        #
        self.vertical_button_box.addWidget(self.upload_button)
        self.vertical_button_box.addWidget(self.format_label)
        self.vertical_button_box.addWidget(self.format_combo_box)
        self.vertical_button_box.addWidget(self.status_label)
        self.vertical_button_box.addWidget(self.parse_button)
        main_layout.addRow(self.vertical_button_box)
        #
        self.parse_button.clicked.connect(self.ConvertPCAP)
        #
        self.setLayout(main_layout)

    def ConvertPCAP(self):
        #
        ParsingOption = self.format_combo_box.currentText()
        #
        if(ParsingOption == 'XLSX'):
            self.status_label.setText("Status: Converting PCAP to XLSX...")
            self.status_label.setStyleSheet("background-color: orange")
            capture = PcapToXLSX(self.rawCapture)
            result = capture.ConvertToXLSX()
            if(result is not False):
                self.status_label.setText("Status: Successful conversion from PCAP to XLSX")
                self.status_label.setStyleSheet("background-color: green")
                converted_file_path = os.path.abspath(str(result))
                time.sleep(1)
                self.status_label.setText("XLSX File may be located at: %s " % converted_file_path)
            else:
                self.status_label.setText("Status: Failed to convert PCAP to XLSX")
                self.status_label.setStyleSheet("background-color: red")
        else:
            return

    def GetFile(self):
        self.rawCapture = ''
        dialog = QFileDialog()
        captureFile = dialog.getOpenFileName(None, "Import PCAP", "", "PCAP Data Files (*.pcap)")
        if(os.path.exists(captureFile[0])):
            self.rawCapture = captureFile[0]
            self.status_label.setText("Status: Valid PCAP Loaded - Ready to Parse")
            self.status_label.setStyleSheet("background-color: blue")
        else:
            return


if(__name__ == '__main__'):
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()
    sys.exit(app.exec_())
