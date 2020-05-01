import json
import sys
import csv
from PyQt5 import QtWidgets, QtCore, Qt
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QWidget, QDesktopWidget, QApplication, QFileDialog, QInputDialog, QAbstractItemView, \
    QTableWidgetItem, QHeaderView, QHBoxLayout
import pandas,numpy

import code.prediction as pc


class Example(QWidget):

    def __init__(self):
        super().__init__()
        self.filename=''
        self.json=()
        self.datax=[]
        self.centralWidget = QtWidgets.QWidget(self)
        self.pushButton = QtWidgets.QPushButton(self.centralWidget)
        self.initUI()


    def initUI(self):
        self.resize(600, 400)
        self.center()

        self.setWindowTitle('恶意函数预测系统')
        self.setWindowIcon(QIcon('logo.jpg'))



        self.pushButton.setGeometry(QtCore.QRect(250, 20, 100, 30))
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setText("选择文件")


        self.pushButton.clicked.connect(self.openfile)

        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def openfile(self):
        openfile_name = QFileDialog.getOpenFileName(self, '请选择文件夹路径', '', 'All Files (*)')
        self.filename = openfile_name[0]
        self.json=self.algorithm(self.filename)
        self.write(self.json)
        print(self.filename)

    def algorithm(self,filename):
        j = pc.prediction("Document/test.csv")
        # with open('data.json', 'r') as jonie:
        #     j = json.loads(jonie.read())
        return j
    def write(self,jsonfile):
        self.tableWidget = QtWidgets.QTableWidget(self.centralWidget)
        self.tableWidget.setGeometry(QtCore.QRect(0, 60, 813, 371))
        self.tableWidget.setObjectName("tableWidget")
        self.tableWidget.setColumnCount(2)
        self.tableWidget.setRowCount(len(jsonfile))
        self.tableWidget.setHorizontalHeaderLabels(['函数名', '状态'])
        self.tableWidget.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.setStyleSheet("selection-background-color:pink")
        i=0
        for key,value in jsonfile.items():
            print([key,value])
            newItem = QTableWidgetItem(key)
            self.tableWidget.setItem(i, 0, newItem)
            newItem = QTableWidgetItem(str(value))
            self.tableWidget.setItem(i, 1, newItem)
            i=i+1
        layout = QHBoxLayout()
        layout.addWidget(self.tableWidget)
        self.setLayout(layout)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())