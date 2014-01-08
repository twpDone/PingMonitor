#!/usr/bin/python

from Tkinter import *
from scapy.all import *
import os
import threading
conf.verb=0

CHAT=True

def evtSend(event):
    send()

def send():
    if CHAT:
        toSend=cConf.pseudo+" : "+e.get()
    else:
        toSend=e.get()

    if toSend.__contains__("/quit"):
        listen._Thread__stop()
	t.destroy()
    else:
        try:
            sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(toSend))
        except (Exception) as ex:
            print(ex)
            print("Longueur du message : "+str(len(toSend)))
        
        e.delete(0,END)

class cConf:
    destination="127.0.0.1"
    pseudo="Demo"
    nf=None
    def setpseudo(cls,newPseudo):
        cls.pseudo=newPseudo
        cls.nf.destroy()
    setpseudo=classmethod(setpseudo)
    def setdest(cls,newDest):
        print "set"
        print newDest
        cls.destination=newDest
        cls.nf.destroy()
    setdest=classmethod(setdest)
    def defpseudo(cls):
        cls.nf=Tk()
        nf=cls.nf
        nf.title("Change nickname")
        lbpseudo=LabelFrame(nf,text="Pseudo")
        lbpseudo.pack()
        nick=Entry(lbpseudo)
        nick.pack()
        nick.insert(END,cls.pseudo)
        bnf=Button(lbpseudo,text="Set",command=lambda : cls.setpseudo(nick.get()))
        bnf.pack()
    defpseudo=classmethod(defpseudo)
    def defconf(cls):
        cls.nf=Tk()
        nf=cls.nf
        nf.title("Destination config")
        routes="broadcasts\n"
        for route in conf.route.routes:
            routes+=str(route[3])+" "+str(route[4])
            routes+="\n"
        lnf=Label(nf,text=routes)
        lnf.pack()
        lbdest=LabelFrame(nf,text="Destination")
        lbdest.pack()
        enf=Entry(lbdest)
        enf.pack()
        enf.insert(END,cls.destination)
        bnf=Button(lbdest,text="Set",command=lambda : cls.setdest(enf.get()))
        bnf.pack()
    defconf=classmethod(defconf)
    def getDest(cls):
        return cls.destination
    getDest=classmethod(getDest)
    

t=Tk()
if CHAT:
    t.title("Ping Chat")
else:
    t.title("Ping Monitor")

m=Menu(t)
m.add_command(label="Config",command=cConf.defconf)


#Hidden feature for chatting
if CHAT:
    m.add_command(label="Nickname",command=cConf.defpseudo)

t.config(menu=m)

fTop=Frame(t)
fTop.pack(side=TOP)

sc=Scrollbar(fTop)
sc.pack(side=RIGHT,fill=Y)
tx=Text(fTop,wrap=WORD,yscrollcommand=sc.set)
tx.pack(side=LEFT,fill=Y)

sc.config(command=tx.yview)

fBot=Frame(t)
fBot.pack(side=BOTTOM)

e=Entry(fBot)
e.pack(side=LEFT)
b=Button(fBot,command=send,text="Send")
b.pack(side=RIGHT)
e.bind('<KeyPress-Return>',evtSend)

def addMsg(p):
    tx.insert(INSERT,"\n("+p[IP].src+") "+p[Raw].load)
    tx.yview_scroll(1,"pages")

listen = threading.Thread(None, sniff, None, (), {"filter":"icmp","prn":lambda p: addMsg(p)})

t.after(20,listen.start)
t.after(0,e.focus)
if CHAT:
    sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(cConf.pseudo+" [has joined]"))
t.mainloop()
listen._Thread__stop()
if CHAT:
    sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(cConf.pseudo+" [has quit]"))
 
