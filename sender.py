import tkinter as tk
import tkinter.ttk as ttk
import tkinter.messagebox
from scapy.all import *


def get_if_name():  # 获取网卡名字
    import os
    if os.name == 'nt':
        return [iface['name'] for iface in get_windows_if_list()]
    return get_if_list()


def is_ip(ip):  # 判断ip是否为合法ip
    try:
        nums = ip.split('.')  # 取出ip的四个段，并判断是不是都是[0,255]的范围
        trueSum = 0
        for i in nums:
            if 0 <= int(i, 10) <= 255:
                trueSum += 1
        if trueSum == 4:
            return True
        return False
    except:
        return False


def is_mac(mac):  # 判断mac是否为合法mac
    try:
        hexs = mac.split(':')  # 取出mac的六个段，并判断是不是都是[0,255]的范围
        if len(hexs) != 6:
            hexs = mac.split('-')
        trueSum = 0
        for i in hexs:
            if 0 <= int(i, 16) <= 255:
                trueSum += 1
        if trueSum == 6:
            return True
        return False
    except:
        return False


class App:
    def __init__(self, master):
        self.master = master
        self.op = tk.IntVar()
        self.op.set(1)
        self.nowif = tk.StringVar()
        self.hwsrc = tk.StringVar()
        self.psrc = tk.StringVar()
        self.hwdst = tk.StringVar()
        self.pdst = tk.StringVar()
        self.info = None
        self.initWidgets()
        self.master.mainloop()

    def initWidgets(self):
        ttk.Label(self.master, text='选择网卡').place(x=20, y=10)
        com = ttk.Combobox(self.master, textvariable=self.nowif, width=51)
        com['value'] = get_if_name()
        com.current(0)
        com.config(state='readonly')
        com.place(x=125, y=10)
        ttk.Label(self.master, text='目的MAC地址').place(x=20, y=50)
        ttk.Entry(self.master, textvariable=self.hwdst).place(x=125, y=50)
        ttk.Label(self.master, text='目的IP地址').place(x=20, y=90)
        ttk.Entry(self.master, textvariable=self.pdst).place(x=125, y=90)
        ttk.Label(self.master, text='源MAC地址').place(x=20, y=130)
        ttk.Entry(self.master, textvariable=self.hwsrc).place(x=125, y=130)
        ttk.Label(self.master, text='源IP地址').place(x=20, y=170)
        ttk.Entry(self.master, textvariable=self.psrc).place(x=125, y=170)
        ttk.Label(self.master, text='报文类型').place(x=20, y=210)
        ttk.Radiobutton(self.master, variable=self.op, text='请求报文', value=1).place(x=125, y=210)
        ttk.Radiobutton(self.master, variable=self.op, text='应答报文', value=2).place(x=200, y=210)
        self.info = tk.Text(self.master, textvariable=self.info, width=29, height=11)
        self.info.place(x=300, y=50)
        ttk.Button(self.master, text='发送', command=self.mysend).place(x=306, y=208)
        ttk.Button(self.master, text='退出', command=self.myquit).place(x=415, y=208)

    def myquit(self):  # 退出函数
        exit(0)

    def mysend(self):  # 发送函数
        try:
            pkt = ARP(op=self.op.get(), hwlen=6, plen=4)  # 构造ARP包
            if is_ip(self.pdst.get()):
                pkt.pdst = self.pdst.get()
            if is_ip(self.psrc.get()):
                pkt.psrc = self.psrc.get()
            if is_mac(self.hwdst.get()):
                pkt.hwdst = self.hwdst.get()
            if is_mac(self.hwsrc.get()):
                pkt.hwsrc = self.hwsrc.get()
            pkt.show()
            send(pkt, iface=self.nowif.get())  # 从网卡iface发送ARP包
            self.pdst.set(pkt.pdst)  # 更新输入框的值
            self.psrc.set(pkt.psrc)
            self.hwdst.set(pkt.hwdst)
            self.hwsrc.set(pkt.hwsrc)
            self.info.insert('end', 'Send 1 packets.\n')  # 更新文本框
            res = '###[ ARP ]### \n'
            res += '  hwtype = 0x1\n'
            res += '  ptype  = IPv4\n'
            res += '  hwlen  = 6\n'
            res += '  plen   = 4\n'
            if self.op.get() == 1:
                res += '  op     = who-has\n'
            else:
                res += '  op     = is-at\n'
            res += '  hwdst  = ' + pkt.hwdst + '\n'
            res += '  pdst   = ' + pkt.pdst + '\n'
            res += '  hwsrc  = ' + pkt.hwsrc + '\n'
            res += '  psrc   = ' + pkt.psrc + '\n'
            self.info.insert('end', res + '\n')
        except:  # 若有异常被抛出，则弹窗警告
            tk.messagebox.showinfo(parent=self.master, title='提示', message='发生错误，请检查各项参数')


master = tk.Tk()
master.title('ArpSender')
master.geometry('542x255+458+200')
master.resizable(False, False)
App(master)
