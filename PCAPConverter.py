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
        QWidget.__init__(self)
        QLabel.__init__(self)
        #
        self.setWindowTitle('PCAP Converter')
        self.setGeometry(800,100,500,800)
        #
        dlg = QFileDialog()
        dlg.setFileMode(QFileDialog.AnyFile)
        dlg.setFilter("Text files (*.txt)")
        filenames = QStringList()

        if dlg.exec_():
            filenames = dlg.selectedFiles()


if(__name__ == '__main__'):
    app = QApplication(sys.argv)
    screen = Window()
    screen.show()
    sys.exit(app.exec_())
