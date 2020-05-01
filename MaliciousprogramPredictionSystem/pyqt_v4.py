import csv
import json
import os
import sys
import time


import numpy
import pandas
import qtawesome
from PyQt5 import Qt, QtCore, QtGui, QtWidgets
from PyQt5.QtChart import QChart, QChartView, QPieSeries
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import (QAbstractItemView, QApplication, QDesktopWidget,
                             QFileDialog, QGridLayout, QHBoxLayout,
                             QHeaderView, QInputDialog, QTableWidgetItem,
                             QWidget)

from code_prediction import prediction as pc


class MainUI(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.filename = ''
        self.json = ()
        self.datax = []
        self.percent = 0.0
        self.setFixedSize(1280, 720)
        self.center()
        #self.setWindowOpacity(0.9)
        self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setWindowTitle('恶意函数预测系统')
        self.setWindowIcon(QIcon('./logo.jpeg'))
        self.setObjectName("MainWindow")
        self.setStyleSheet("#MainWindow{border-image:url(./bg.jpg);}")
        self.main_widget = QtWidgets.QWidget()  # 创建窗口主部件
        self.main_layout = QtWidgets.QGridLayout()  # 创建主部件的网格布局
        self.main_widget.setLayout(self.main_layout)  # 设置窗口主部件布局为网格布局

        self.left_widget = QtWidgets.QWidget()  # 创建左侧部件
        self.left_widget.setObjectName('left_widget')
        self.left_layout = QtWidgets.QGridLayout()  # 创建左侧部件的网格布局层
        self.left_widget.setLayout(self.left_layout)  # 设置左侧部件布局为网格

        self.left_up_widget = QtWidgets.QWidget()  # 创建左侧部件的上半部件
        self.left_up_widget.setObjectName('left_up_widget')
        self.left_up_layout = QtWidgets.QGridLayout()  # 创建左侧部件的网格布局层
        self.left_up_widget.setLayout(self.left_up_layout)  # 设置左侧部件布局为网格

        self.left_down_widget = QtWidgets.QWidget()  # 创建左侧部件的下半部件
        self.left_down_widget.setObjectName('left_down_widget')
        self.left_down_layout = QtWidgets.QGridLayout()  # 创建左侧部件的网格布局层
        self.left_down_widget.setLayout(self.left_down_layout)  # 设置左侧部件布局为网格

        self.left_layout.addWidget(self.left_down_widget, 0, 0, 9, 2)
        self.left_layout.addWidget(self.left_up_widget, 9, 0, 3, 2)

        self.main_layout.addWidget(self.left_widget, 0, 0, 12, 8)  # 左侧部件在第0行第0列，占8行3列
        self.setCentralWidget(self.main_widget)  # 设置窗口主部件

        self.pushButton = QtWidgets.QPushButton()
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setText("上传")
        self.pushButton.setFont(QFont("Times", 10))
        self.pushButton.setFixedWidth(120)
        self.pushButton.setFixedHeight(30)
        self.pushButton.setStyleSheet('''QPushButton{background:#FDFFDF;border-radius:15px;}QPushButton:hover{background:#E08031;}''')
        self.left_up_layout.addWidget(self.pushButton, 0, 0, 1, 1)
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
        self.json = self.algorithm(self.filename)
        self.write(self.json)
        print(self.filename)

    def algorithm(self,filename):
        cmd = "ida64 -A -S\"Z:\\Users\\zhangbo\\Desktop\\PredictionSystem\\code_prediction\\extract_trace_v3.py\" \"Z:\\Users\\zhangbo\\Desktop\\linux程序\\bc\""
        cmd2 = "ida64 -A -S\"Z:\\Users\\zhangbo\\Desktop\\PredictionSystem\\code_prediction\\extract_trace_v3.py\" " +"\""+filename+"\""
        print(cmd2)
        # print(cmd)
        time_start=time.time()

        os.system(cmd2)
        test_path = filename[:filename.rfind("/")+1]+"test.csv"
        print(test_path)
        while(1):
            if(os.path.exists(test_path)):
                break
        time_end=time.time()
        print('time cost',time_end-time_start,'s')
        j = pc.prediction(test_path)
        j = json.loads(j)
        os.remove(test_path)
        # print(j)
        return j

    #def paintEvent(self, event):  # set background_img
    #    painter = QPainter(self)
    #    painter.drawRect(self.rect())
     #   pixmap = QPixmap("./bg.jpg")  # 换成自己的图片的相对路径
     #   painter.drawPixmap(self.rect(), pixmap)

    def write(self, jsonfile):
        self.setStyleSheet("#MainWindow{border-image:url(./bg2.jpg);}")
        self.left_up_layout.addWidget(self.pushButton, 0, 0, 1, 1)
        self.pushButton1 = QtWidgets.QPushButton()
        self.pushButton1.setObjectName("pushButton1")
        self.pushButton1.setText("分析")
        self.pushButton1.setFont(QFont("Times", 10))
        self.pushButton1.setFixedWidth(120)
        self.pushButton1.setFixedHeight(30)
        self.pushButton1.setStyleSheet(
            '''QPushButton{background:#FDFFDF;border-radius:15px;}QPushButton:hover{background:#E08031;}''')
        self.left_up_layout.addWidget(self.pushButton1, 1, 0, 1, 1)
        self.pushButton1.clicked.connect(self.analyse)
        self.pushButton2 = QtWidgets.QPushButton()
        self.pushButton2.setObjectName("pushButton2")
        self.pushButton2.setText("退出")
        self.pushButton2.setFont(QFont("Times", 10))
        self.pushButton2.setFixedWidth(120)
        self.pushButton2.setFixedHeight(30)
        self.pushButton2.setStyleSheet(
            '''QPushButton{background:#FDFFDF;border-radius:15px;}QPushButton:hover{background:#E08031;}''')
        self.left_up_layout.addWidget(self.pushButton2, 2, 0, 1, 1)
        self.pushButton2.clicked.connect(self.close)
        self.right_widget = QtWidgets.QTableWidget()  # 创建右侧部件
        self.right_widget.setObjectName('right_widget')
        self.right_layout = QtWidgets.QGridLayout()
        self.right_widget.setLayout(self.right_layout)  # 设置右侧部件布局为网格

        self.main_layout.addWidget(self.right_widget, 0, 8, 12, 4)  # 右侧部件在第0行第3列，占8行9列
        self.right_widget.setColumnCount(2)
        self.right_widget.setRowCount(len(jsonfile))
        self.right_widget.setHorizontalHeaderLabels(['函数名', '状态'])
        self.right_widget.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.right_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        # self.right_widget.setStyleSheet("selection-background-color:pink")
        self.right_widget.setColumnWidth(0, 100)
        self.right_widget.setColumnWidth(1, 100)
        i = 0
        x = 0
        for key, value in jsonfile.items():
            # print([key, value])
            newItem = QTableWidgetItem(key)
            self.right_widget.setItem(i, 0, newItem)
            newItem = QTableWidgetItem(str(value))
            self.right_widget.setItem(i, 1, newItem)
            if value == 0:
                self.right_widget.item(i, 0).setBackground(QBrush(QColor(255,83,77)))
                self.right_widget.item(i, 1).setBackground(QBrush(QColor(255,83,77)))
                x += 1
            i = i + 1
        self.percent = x / i
        self.show()
        self.chartx()

    def analyse(self):
        print(self.filename)
        cmd2 = "ida64 -S\"Z:\\Users\\zhangbo\\Desktop\\PredictionSystem\\code_prediction\\trace.py\" " +"\""+self.filename+"\""
        os.system(cmd2)
        
    def chartx(self):
        self.pieseries = QPieSeries()  # 定义PieSeries
        self.pieseries.append("正常程序", 1 - self.percent)  # 插入第一个元素
        self.pieseries.append("恶意程序", self.percent)

        self.slice = self.pieseries.slices()[0]  # 得到饼图的某一个元素切片，在这取得为第一个
        # self.slice.setExploded()  # 设置为exploded
        self.slice.setLabelVisible()  # 设置Lable
        self.slice.setPen(QPen(Qt.darkGreen, 1))  # 设置画笔类型
        self.slice.setBrush(QBrush(QColor(25,148,117)))  # 设置笔刷
        self.slice1 = self.pieseries.slices()[1]  # 得到饼图的某一个元素切片，在这取得为第一个
        self.slice1.setExploded()  # 设置为exploded
        self.slice1.setLabelVisible()  # 设置Lable
        self.slice1.setPen(QPen(Qt.darkRed, 1))  # 设置画笔类型
        self.slice1.setBrush(QBrush(QColor(255,83,77)))  # 设置笔刷
        self.chart = QChart()  # 定义QChart
        self.chart.addSeries(self.pieseries)  # 将 pieseries添加到chart里
        self.chart.setTitle("恶意程序预测结果饼状图")  # 设置char的标题
        self.chart.legend().hide()  # 将char的legend设置为隐藏
        self.charview = QChartView(self.chart,
                                   self.left_down_widget)  # 定义charView窗口，添加chart元素，设置主窗口为父窗体，既将chartView嵌入到父窗体
        self.charview.setGeometry(0, 0, 800, 500)  # 设置charview在父窗口的大小、位置
        self.charview.setRenderHint(QPainter.Antialiasing)  # 设置抗锯齿
        self.charview.show()  # 将CharView窗口显示出来


if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = MainUI()
    print(Qt.green)
    gui.show()
    sys.exit(app.exec_())
