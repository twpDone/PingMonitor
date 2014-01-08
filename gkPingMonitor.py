#!/usr/bin/python
#coding:utf-8

from Tkinter import *
from scapy.all import *
import os
import threading

conf.verb=0 # Desactivation de la verbosite de scapy

CHAT=True # Boolean : chat mode

def evtSend(event):
    #Event (handler) pour l'envoi
    send()

def send():
    # Envoi des données
    
    # Si le chat est activé on ajoute le pseudo en debut de message
    # e.get() recuperation du texte dans l'entree 
    if CHAT:
        toSend=cConf.pseudo+" : "+e.get()
    else:
        toSend=e.get()
    # Si le message contient /quit, quitter l'app
    if toSend.__contains__("/quit"):
        listen._Thread__stop()
	t.destroy()
    else:
        # Sinon envoyer le message
        try:
            """
            Utilisation de la methode statique 
            de la class cConf permettant de
            recuperer ip de destination
            """
            sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(toSend))
        except (Exception) as ex:
            print(ex)
            print("Longueur du message : "+str(len(toSend)))
        
        e.delete(0,END) # Effacer l'input text (Entry e)

class cConf:
    """
    Class cConf permettant de recuperer la conf de l'app
    via attributs statiques
    """
    destination="127.0.0.1"
    pseudo="Demo"
    nf=None #nf for new frame, nouvelle fenetre de conf
    def setpseudo(cls,newPseudo):
        cls.pseudo=newPseudo
        cls.nf.destroy() 
        """ Destruction de la fenetre de conf une fois 
            le nouveau pseudo defini """
    setpseudo=classmethod(setpseudo)
    def setdest(cls,newDest):
        print "set"
        print newDest
        cls.destination=newDest
        cls.nf.destroy()
        """ Destruction de la fenetre de conf une fois 
            la nouvelle ip de destination definie """
    setdest=classmethod(setdest)
    def defpseudo(cls):
        # Methode pour la configuration du pseudo

        # Intanciation de la fenetre de conf et de ses composants
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
        # Methode pour la configuration de l'ip de destination

        # Intanciation de la fenetre de conf et de ses composants
        cls.nf=Tk()
        nf=cls.nf
        nf.title("Destination config")
        routes="broadcasts\n"
        # utilisation de scapy pour recuperer les adresses des interfaces
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
        # methode de classe pour recuperer l'ip de destination
        return cls.destination
    getDest=classmethod(getDest)
    
# === Main ===

t=Tk()
# Definir le titre de la fenetre
if CHAT:
    t.title("Ping Chat")
else:
    t.title("Ping Monitor")

m=Menu(t)
m.add_command(label="Config",command=cConf.defconf) # menu de config por l'ip de destination


#Hidden feature for chatting
if CHAT:
    m.add_command(label="Nickname",command=cConf.defpseudo) # menu de config por le pseudo

t.config(menu=m) # lier le menu a la fenetre

# creation d'un frame contenant un champ de texte scrollable pour l'affichage des message
fTop=Frame(t)
fTop.pack(side=TOP)

sc=Scrollbar(fTop)
sc.pack(side=RIGHT,fill=Y)
tx=Text(fTop,wrap=WORD,yscrollcommand=sc.set)
tx.pack(side=LEFT,fill=Y)

sc.config(command=tx.yview)

# creation d'un fram pour la saisie des messages
fBot=Frame(t)
fBot.pack(side=BOTTOM)

e=Entry(fBot)
e.pack(side=LEFT)
b=Button(fBot,command=send,text="Send")
b.pack(side=RIGHT)
e.bind('<KeyPress-Return>',evtSend) # lier l'event sur appui de la touche Retour/Entree pour l'event d'envoi des messages

def addMsg(p):
    #fonction pour l'ajout des message dans la zone de texte
    tx.insert(INSERT,"\n("+p[IP].src+") "+p[Raw].load)
    tx.yview_scroll(1,"pages")

# preparation du thread de reception des paquet icmp 
# la reception d'un paquet correspondant au filtre appelle le callback d'addMsg
listen = threading.Thread(None, sniff, None, (), {"filter":"icmp","prn":lambda p: addMsg(p)})

# lancement apres "main loop" du thread  d'ecoute
#le thread doit etre lance avec after sinon l'interface ne peut pas etre utilisee par le thread
t.after(20,listen.start) # lancement du thread de l'interface graphique
t.after(0,e.focus) # passage du focus a la zone de saisie
if CHAT:
    sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(cConf.pseudo+" [has joined]")) # annonce du join utilisateur
t.mainloop()
listen._Thread__stop()
if CHAT:
    sendp(Ether()/IP(dst=cConf.getDest())/ICMP()/(cConf.pseudo+" [has quit]")) # annonce du quit utilisateur
 
