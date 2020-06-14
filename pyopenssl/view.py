# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'self.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!
import sys
import os
import tkinter as tk
from tkinter import filedialog
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QFileDialog
import numpy as np
import subprocess
from hash import M_digesrts


class Ui_MainWindow(object):
    def __init__(self):
        self.sourcevideopath = '/home/bly/11.docx'
        self.digestfile = '/home/bly/11.txt'

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(350, 500)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        self.frame = QtWidgets.QFrame(self.centralwidget)
        self.frame.setGeometry(QtCore.QRect(50, 50, 260, 50))
        self.frame.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame.setObjectName("frame")

        self.LaXiaozu = QtWidgets.QLabel(self.centralwidget)
        self.LaXiaozu.setObjectName("LaXiaozu")
        self.LaXiaozu.setGeometry(QtCore.QRect(50, 30, 80, 20))
        self.LaXiaozu.setText("小组成员")

        self.label_name=QtWidgets.QLabel(self.frame)
        self.label_name.setObjectName("Disname")
        self.label_name.setText("组长：曲恒熠\n组员：包聆言 敖小双 赵孟山")
        #self.horizontalLayout.addWidget(self.label)

        #视频风格化区
        self.frame3 = QtWidgets.QFrame(self.centralwidget)
        self.frame3.setGeometry(QtCore.QRect(50, 150, 260, 150))
        self.frame3.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame3.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame3.setObjectName("frame2")

        self.La_batch = QtWidgets.QLabel(self.frame3)
        self.La_batch.setObjectName("Labatch")
        self.La_batch.setText("选择进行摘要还是验证：")
        self.La_batch.setGeometry(QtCore.QRect(0, 0, 120, 20))

        self.Batch = QtWidgets.QComboBox(self.frame3)
        self.Batch.setObjectName("VideoStyle")
        self.Batch.setGeometry(QtCore.QRect(120, 0, 120, 20))
        self.Batch.addItem("摘要")
        self.Batch.addItem("验证")

        self.La_vistyle = QtWidgets.QLabel(self.frame3)
        self.La_vistyle.setObjectName("ChoVistyle")
        self.La_vistyle.setText("选择相应算法：")
        self.La_vistyle.setGeometry(QtCore.QRect(0, 30, 120, 20))

        self.HashStyle = QtWidgets.QComboBox(self.frame3)
        self.HashStyle.setObjectName("VideoStyle")
        self.HashStyle.setGeometry(QtCore.QRect(120, 30, 120, 20))
        self.HashStyle.addItem("SHA256")
        self.HashStyle.addItem("SHA512")
        self.HashStyle.addItem("SHA1")
        self.HashStyle.addItem("MD5")
        self.HashStyle.addItem("SHA224")
        self.HashStyle.addItem("SHA512")

        self.La_video = QtWidgets.QLabel(self.frame3)
        self.La_video.setObjectName("Sevideo")
        self.La_video.setText("选择需要处理的文件：")
        self.La_video.setGeometry(QtCore.QRect(0, 60, 120, 20))

        self.But_video = QtWidgets.QPushButton(self.frame3)
        self.But_video.setObjectName("Opvideo")
        self.But_video.setText("选择文件")
        self.But_video.setGeometry(QtCore.QRect(120, 60, 80, 20))
        self.But_video.clicked.connect(self.getvideopath)

        self.La_difile = QtWidgets.QLabel(self.frame3)
        self.La_difile.setObjectName("Sevideo")
        self.La_difile.setText("选择保存了摘要的文件：")
        self.La_difile.setGeometry(QtCore.QRect(0, 90, 120, 20))

        self.But_video = QtWidgets.QPushButton(self.frame3)
        self.But_video.setObjectName("Opvideo")
        self.But_video.setText("摘要文件")
        self.But_video.setGeometry(QtCore.QRect(120, 90, 80, 20))
        self.But_video.clicked.connect(self.getdigestfile)

        # 风格化按钮
        self.ButtrVideo = QtWidgets.QPushButton(self.frame3)
        self.ButtrVideo.setGeometry(QtCore.QRect(160, 120, 80, 20))
        self.ButtrVideo.setText("运行")
        self.ButtrVideo.clicked.connect(self.tranvideo)

    def getvideopath(self):
        sourcevide = tk.filedialog.askopenfilename()
        self.sourcevideopath = sourcevide

    def getdigestfile(self):
        digestfilepath = tk.filedialog.askopenfilename()
        self.digestfile = digestfilepath

    def tranvideo(self):
        di = M_digesrts()
        # 得到hashstyle的方式
        HashStyle = self.HashStyle.currentText()
        srcfile = self.sourcevideopath
        #判断需要进行摘要还是验证
        flag = self.Batch.currentText()

        #进行摘要
        if flag == "摘要":
            #得到相应文件的数字摘要
            digest =  di.caldigests(srcfile,HashStyle)
            #将摘要写入文件中保存
            di.writedigest(srcfile,digest)
        #进行验证
        else:
            digestfile = self.digestfile
            srcdigest = di.caldigests(srcfile, HashStyle)
            flag1 = di.check(str(srcdigest), digestfile)
            if flag1:
                print('文件正确')
            else:
                print('文件被修改')
                exit()

if __name__=='__main__':
    app=QtWidgets.QApplication(sys.argv)
    windows = QtWidgets.QWidget()
    ui=Ui_MainWindow()
    ui.setupUi(windows)
    windows.show()
    sys.exit(app.exec_())
