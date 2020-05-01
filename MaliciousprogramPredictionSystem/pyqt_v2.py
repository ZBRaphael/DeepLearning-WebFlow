import csv
import json
import sys
import os

import numpy
import pandas
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

import qtawesome
from code_prediction import prediction as pc


class MainUI(QtWidgets.QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()


    def initUI(self):
        self.filename=''
        self.json=()
        self.datax=[]
        self.setFixedSize(1280, 720)
        self.center()
        self.setWindowOpacity(0.9)
        #self.setWindowFlag(QtCore.Qt.FramelessWindowHint)
        self.setWindowTitle('恶意函数预测系统')
        spin_icon = qtawesome.icon('fa5b.github', color='black')
        self.setWindowIcon(spin_icon)

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

        self.left_layout.addWidget(self.left_up_widget,0,0,3,2)
        self.left_layout.addWidget(self.left_down_widget, 3, 0, 9, 2)


        self.main_layout.addWidget(self.left_widget, 0, 0, 12, 8)  # 左侧部件在第0行第0列，占8行3列
        self.setCentralWidget(self.main_widget)  # 设置窗口主部件

        self.pushButton = QtWidgets.QPushButton()
        self.pushButton.setObjectName("pushButton")
        self.pushButton.setText("选择文件")
        self.pushButton.setFont(QFont("Times", 18))
        self.pushButton.setFixedWidth(300)
        self.pushButton.setFixedHeight(100)
        self.pushButton.setStyleSheet('''QPushButton{border:none;} QPushButton:hover{color:white; 
        border:2px solid #F3F3F5; border-radius:35px; background:darkGray;}''' )
        self.left_up_layout.addWidget(self.pushButton, 0, 0, 1,1)
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
        cmd = "ida64 -A -S\"Z:\\Users\\zhangbo\\Desktop\\PredictionSystem\\code_prediction\\extract_trace_v3.py\" \"Z:\\Users\\zhangbo\\Desktop\\linux程序\\bc\""
        cmd2 = "ida64 -A -S\"Z:\\Users\\zhangbo\\Desktop\\PredictionSystem\\code_prediction\\extract_trace_v3.py\" " +"\""+filename+"\""
        print(cmd2)
        # print(cmd)
        os.system(cmd2)
        while(1):
            if(os.path.exists("./Document/test.csv")):
                break
        j = pc.prediction("./Document/test.csv")
        j = json.loads(j)
        os.remove("./Document/test.csv")
        # print(j)
        return j

    def paintEvent(self, event):  # set background_img
        painter = QPainter(self)
        painter.drawRect(self.rect())
        pixmap = QPixmap("./bg.png")  # 换成自己的图片的相对路径
        painter.drawPixmap(self.rect(), pixmap)

    def write(self,jsonfile):
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
        #self.right_widget.setStyleSheet("selection-background-color:pink")
        self.right_widget.setColumnWidth(0,100)
        self.right_widget.setColumnWidth(1, 100)
        i=0
        for key,value in jsonfile.items():
            # print([key,value])
            newItem = QTableWidgetItem(key)
            self.right_widget.setItem(i, 0, newItem)
            newItem = QTableWidgetItem(str(value))
            self.right_widget.setItem(i, 1, newItem)
            i=i+1

        self.right_widget.item(0,0).setBackground(QBrush(QColor(255, 0, 0)))
        self.right_widget.item(0, 1).setBackground(QBrush(QColor(255, 0, 0)))
        self.right_widget.item(1, 0).setBackground(QBrush(QColor(0, 255, 0)))
        self.right_widget.item(1, 1).setBackground(QBrush(QColor(0, 255, 0)))
        self.show()
        self.chart()
    def chart(self):
        self.pieseries = QPieSeries()  # 定义PieSeries
        self.pieseries.append("正常程序", 0.1)  # 插入第一个元素
        self.pieseries.append("恶意程序", 0.9)

        self.slice = self.pieseries.slices()[0]  # 得到饼图的某一个元素切片，在这取得为第一个
        #self.slice.setExploded()  # 设置为exploded
        self.slice.setLabelVisible()  # 设置Lable
        self.slice.setPen(QPen(Qt.darkGreen, 1))  # 设置画笔类型
        self.slice.setBrush(Qt.green)  # 设置笔刷
        self.slice1 = self.pieseries.slices()[1]  # 得到饼图的某一个元素切片，在这取得为第一个
        self.slice1.setExploded()  # 设置为exploded
        self.slice1.setLabelVisible()  # 设置Lable
        self.slice1.setPen(QPen(Qt.darkRed, 1))  # 设置画笔类型
        self.slice1.setBrush(Qt.red)  # 设置笔刷
        self.chart = QChart()  # 定义QChart
        self.chart.addSeries(self.pieseries)  # 将 pieseries添加到chart里
        self.chart.setTitle("恶意程序预测结果饼状图")  # 设置char的标题
        self.chart.legend().hide()  # 将char的legend设置为隐藏

        self.charview = QChartView(self.chart, self.left_down_widget)  # 定义charView窗口，添加chart元素，设置主窗口为父窗体，既将chartView嵌入到父窗体
        self.charview.setGeometry(0,0, 800,500)  # 设置charview在父窗口的大小、位置
        self.charview.setRenderHint(QPainter.Antialiasing)  # 设置抗锯齿
        self.charview.show()  # 将CharView窗口显示出来

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui =MainUI()

    gui.show()
    sys.exit(app.exec_())
