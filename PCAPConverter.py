#!/usr/bin/env python3

try:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    import time
    import sys
except Exception as e:
    print("[!] Library import error: %s " % e)

class Window(QWidget):

    def __init__(self):
        #
        QWidget.__init__(self)
        QLabel.__init__(self)
        #
        self.setWindowTitle('PCAP Converter')
        self.setGeometry(500,100,300,300)
        #
        self.upload_button = QPushButton("Upload PCAP File", self)
        self.upload_button.clicked.connect(self.GetFile)
        #
        self.parse_button = QPushButton("Convert PCAP", self)
        self.parse_button.clicked.connect(self.GetFile)
        #
        self.format_label      = QLabel("Format")        
        self.format_combo_box  = QComboBox() 
        self.format_combo_box.addItem('CSV')
        self.format_combo_box.addItem('XLSX')
        self.format_combo_box.addItem('TXT')  
        #
        main_layout              = QFormLayout()
        self.vertical_button_box = QVBoxLayout()
        #
        self.vertical_button_box.addWidget(self.upload_button)
        self.vertical_button_box.addWidget(self.format_label)
        self.vertical_button_box.addWidget(self.format_combo_box)
        self.vertical_button_box.addWidget(self.parse_button)
        main_layout.addRow(self.vertical_button_box)
        #
        self.setLayout(main_layout)

    def GetFile(self):
        dialog = QFileDialog()
        fname = dialog.getOpenFileName(None, "Import CSV", "", "PCAP Data Files (*.pcap)")
        print(fname)


if(__name__ == '__main__'):
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()
    sys.exit(app.exec_())
