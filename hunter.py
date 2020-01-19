import tkinter as tk
import tkinter.ttk as ttk
from scapy.all import *


def get_if_name():  # 获取网卡名字
    import os
    if os.name == 'nt':
        return [iface['name'] for iface in get_windows_if_list()]
    return get_if_list()


class App:  # 界面设计
    def __init__(self, master):
        self.master = master
        self.nowif = tk.StringVar()
        self.thread = None
        self.stbu = None
        self.now = 0.0
        self.num = 1
        self.tree = None
        self.text = None
        self.initWidgets()
        self.master.mainloop()

    def initWidgets(self):
        ttk.Label(self.master, text='选择网卡').place(x=20, y=10)
        com = ttk.Combobox(self.master, textvariable=self.nowif, width=90)
        com['value'] = get_if_name()
        com.current(0)
        com.config(state='readonly')
        com.place(x=100, y=10)
        self.stbu = ttk.Button(self.master, text='开始', command=self.start)
        self.stbu.place(x=25, y=50)
        ttk.Button(self.master, text='停止', command=self.stop).place(x=236, y=50)
        ttk.Button(self.master, text='清除所有', command=self.clear).place(x=447, y=50)
        ttk.Button(self.master, text='退出', command=self.quit).place(x=658, y=50)
        self.tree = ttk.Treeview(self.master, height=10,
                                 column=('编号', '协议类型', '时间', '长度(B)', '目的MAC地址', '目的IP地址', '源MAC地址', '源IP地址'))
        self.tree.column('编号', width=50, anchor='center')
        self.tree.column('协议类型', width=80, anchor='center')
        self.tree.column('时间', width=90, anchor='center')
        self.tree.column('长度(B)', width=55, anchor='center')
        self.tree.column('目的MAC地址', width=110, anchor='w')
        self.tree.column('目的IP地址', width=110, anchor='w')
        self.tree.column('源MAC地址', width=110, anchor='w')
        self.tree.column('源IP地址', width=110, anchor='w')

        self.tree.heading('编号', text='编号')
        self.tree.heading('协议类型', text='协议类型')
        self.tree.heading('时间', text='时间')
        self.tree.heading('长度(B)', text='长度(B)')
        self.tree.heading('目的MAC地址', text='目的MAC地址')
        self.tree.heading('目的IP地址', text='目的IP地址')
        self.tree.heading('源MAC地址', text='源MAC地址')
        self.tree.heading('源IP地址', text='源IP地址')

        self.tree.bind('<Double-1>', self.OnDoubleClick)
        self.tree.config(show='headings')
        self.tree.place(x=25, y=90)

        vbar = ttk.Scrollbar(self.master, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vbar.set)
        vbar.place(x=743, y=89, height=230)

        self.text = tk.Text(self.master, width=102, height=11)
        self.text.place(x=25, y=335)

    def OnDoubleClick(self, event):
        item = self.tree.identify('item', event.x, event.y)
        val = self.tree.item(item, 'values')
        if isinstance(val, tuple):
            print(val)
            self.text.delete('0.0', 'end')
            self.text.insert('end',
                             'Hunt 1 packets.\n###[ ARP ]###\n  hwtype = 0x1\n  ptype  = IPv4\n  hwlen  = 6\n  plen   = 4\n')
            self.text.insert('end', '  op     = ' + val[1] + '\n')
            self.text.insert('end', '  hwdst  = ' + val[4] + '\n')
            self.text.insert('end', '  pdst   = ' + val[5] + '\n')
            self.text.insert('end', '  hwsrc  = ' + val[6] + '\n')
            self.text.insert('end', '  psrc   = ' + val[7])

        else:
            print('error')

    def insert_data(self, data):  # 向表格中插入数据
        if self.now == 0.0:  # 从抓到的第一个包开始计时
            self.now = time.clock()
        nowtime = time.clock() - self.now
        nowtime = '%.6f' % nowtime
        arp_type = 'who_is' if data.op == 1 else 'is_at'  # 判断抓到的包的类型
        self.tree.insert('', 'end',
                         values=(self.num, arp_type, nowtime, len(data), data.hwdst, data.pdst, data.hwsrc, data.psrc))
        self.num += 1  # 包的编号加一

    def sniffing(self):  # 抓包核心函数
        self.thread = AsyncSniffer(count=0, filter='arp', iface=self.nowif.get(), prn=self.insert_data)

    def start(self):  # 开始抓包
        self.clear()  # 清空表格
        self.now = 0.0  # 初始化抓包的时间为0
        self.num = 1  # 初始化包的编号为1
        if self.thread is not None:  # 若正在抓包，则先停止抓包
            self.stop()
        self.sniffing()  # 调用抓包核心函数
        self.thread.start()  # 启动线程
        self.stbu.config(state='disabled')  # 使开始按钮变得不可点击

    def stop(self):  # 停止抓包
        if self.thread is not None:  # 若正在抓包，则停止抓包
            self.thread.stop()
            self.thread = None
        self.stbu.config(state='normal')  # 使开始变得可点击

    def clear(self):  # 清空表格
        for i in self.tree.get_children():  # 循环表格的每个儿子并删除
            self.tree.delete(i)

    def quit(self):  # 退出程序
        self.stop()  # 先停止抓包
        exit(0)  # 再退出


master = tk.Tk()
master.title('ArpHunter')
master.geometry('770x505+405+200')
master.resizable(False, False)
App(master)
