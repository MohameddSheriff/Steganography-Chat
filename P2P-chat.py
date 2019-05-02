#!/usr/bin/python3


from tkinter import *
from PIL import ImageTk, Image
import sys
import socket
import _thread
import threading
import time
import datetime
import cv2
import random
#
# Global variables
#

username = "" 							#Store the username that is defined by the user
clientStatus = "STARTED"					#The status of the client as dictated by the state diagram
chatHashID = ""							#The chat's hashID after joining a chat room, to be used for comparing with new hash ID on each KEEPALIVE request.
msgID = 0							#message ID of the last message sent
myRoom = ""							#Name of the room currently joined
membersList = []						#List of information of all members in the chat room
backlinks = []							#Array of tuples containing information of the backward linked clients, along with the socket to contact them
forwardLink = ()						#Tuple containing information of the forward linked client, along with the socket to contact them
messages = []							#Array storing the messages received (the hash ID of the sender, along with the msgID)
hashes = []							#Array of tuples containing information of members, along with their hash ID
lock = threading.Lock()						#mutex lock for messages array as it is shared between threads who append data to array; we dont want them to append together = 
								#could lead to duplication of messages if two threads i.e. two clients try to forward the same message at the same time 
flag = False
imageFlag = False
users = dict()
users['ramy','1234'] = 8000
users['fox','12345'] = 8001
users['sherif','123'] = 8002
users['hany','12'] = 8003

def sdbm_hash(instr):
	hash = 0
	for c in instr:
		hash = int(ord(c)) + (hash << 6) + (hash << 16) - hash
	return hash & 0xffffffffffffffff


#
# Functions to handle user input
#

def do_User():
	global clientStatus
								#If userentry is not empty
	if clientStatus != "JOINED" and clientStatus != "CONNECTED":			#and they have not joined a chat room
		global username								#access the global variables . . 
		clientStatus = "NAMED"							# . . and store the new values
		CmdWin.insert(1.0, "\n[User] username: "+username)
		userentry.delete(0, END)
	else:
		CmdWin.insert(1.0, "\nCannot change username after joining a chatroom!")

def do_List():
	msg = "L::\r\n"
	try:
		roomServerSocket.send(msg.encode("ascii"))
		response = roomServerSocket.recv(1024)							#Receive the response
		response = str(response.decode("ascii"))						#Convert from bytearray to string
		if response:
			if response[0] == 'G':									#Check if first char is G, signifying a successful request
				response = response[2:-4]							#Trim the G: and ::\r\n from the response
				if len(response) == 0:								#if response body is empty, no chat rooms exist
					CmdWin.insert(1.0, "\nNo active chatrooms")
				else:										#else, split the array using the : char, and output to CmdWin
					rooms = response.split(":")
					for room in rooms:
						CmdWin.insert(1.0, "\n\t"+room)
					CmdWin.insert(1.0, "\nHere are the active chat rooms:")	
			elif response[0] == 'F':
				response = response[2:-4]								#If first char is F, it is an error.
				CmdWin.insert(1.0, "\nError fetching chatroom list: "+response)
		else:
			raise socket.error("IndexError due to broken socket")	
	except socket.error as err:
		print(str(err))
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (do_List, ))		#Start a new thread to make a connection with the room server

def chunker(array, chunkSize):
    return (array[pos:pos + chunkSize] for pos in range(0, len(array), chunkSize))	

def do_Join():
	global clientStatus
	try:
		if userentry.get():
			if username != "":
				if not (clientStatus == "JOINED" or clientStatus == "CONNECTED"):
					global roomname 
					roomname = userentry.get()
					msg = "J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n"
					roomServerSocket.send(msg.encode("ascii"))
					response = roomServerSocket.recv(1024)
					response = str(response.decode("ascii"))
					
					if response:
						if response[0] == 'M':	
							response = response[2:-4]				#Trim the M: and ::\r\n from the response
							members = response.split(":")				#Split the array using the : char

							global chatHashID 
							chatHashID = members[0]					#Store chathash to check if member list changed later on

							global membersList
							CmdWin.insert(1.0, "\nJoined chat room: "+roomname)
							for group in chunker(members[1:], 3):			#Break array into array of arrays, each containing the username, IP and port for contacting
								membersList.append(group)
								CmdWin.insert(1.0, "\n\t"+str(group))
							CmdWin.insert(1.0, "\nHere are the members:")	
							clientStatus = "JOINED"					#Status is now JOINED
							userentry.delete(0, END)
					
							global myRoom
							myRoom = roomname					#Store roomname joined
							_thread.start_new_thread (keepAliveProcedure, ())	#Start a new thread runnning the keepAliveProcedure
							_thread.start_new_thread (serverProcedure, ())		#Start a new thread runnning the server part of P2P
							findP2PPeer(membersList)				#Find a peer to connect via
						elif response[0] == 'F':
							response = response[2:-4]
							CmdWin.insert(1.0, "\nError performing JOIN req: "+response)
					else:
						raise socket.error("IndexError due to broken socket")
				else:
					CmdWin.insert(1.0, "\nAlready joined/connected to another chatroom!!")
			else:
				CmdWin.insert(1.0, "\nPlease set username first.")
		else:
			CmdWin.insert(1.0, "\nPlease enter room name!")
	except socket.error as err:
		print(str(err))
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (do_Join, ))		#Start a new thread to make a connection with the room server


def keepAliveProcedure():
	CmdWin.insert(1.0, "\nStarted KeepAlive Thread")
	while roomServerSocket:						#While the serversocket is intact, keep sending a join request . . . 
		time.sleep(20)						# . . . every 20 seconds
		updateMembersList("Keep Alive")				#Performs the JOIN request, also updates member list
		if clientStatus == "JOINED" or not forwardLink:		#If client is still not CONNECTED, i.e. still in JOINED state, look for a peer
			global membersList
			findP2PPeer(membersList)
	
def serverProcedure():
	sockfd = socket.socket()
	sockfd.bind( ('', int(myPort)) )				#Create a socket on current IP, with port set as listening port
	while sockfd:
		sockfd.listen(5)					
		conn, address = sockfd.accept()
		print ("Accepted connection from" + str(address))	
		response = conn.recv(1024)				#Wait for P2P handshake message
		response = str(response.decode("ascii"))
		
		if response:
			if response[0] == 'P':					#If peer initiated P2P handshake . . 
				response = response[2:-4]			#Collect all info about the handshaker
				connectorInfo = response.split(":")
				connectorRoomname = connectorInfo[0]
				connectorUsername = connectorInfo[1]
				connectorIP = connectorInfo[2]
				connectorPort = connectorInfo[3]
				connectorMsgID = connectorInfo[4]
				global membersList			
				try:						
					memberIndex = membersList.index(connectorInfo[1:4])				#check if initiating peer is in current member list
				except ValueError:									#error thrown if can't find . . 
					if updateMembersList("Server Procedure"):					# . . so get updated memberlist from sever
						try:
							memberIndex = membersList.index(connectorInfo[1:4])		#retry looking for initiating peer 
						except ValueError:							#error thrown if can't find . . 
							memberIndex = -1						# . . so it is some unknown peer, reject connection
							print("Unable to connect to " + str(address))
							conn.close()
					else:
						print("Unable to update member's list, so connection was rejected.")
						conn.close()					
				if memberIndex != -1:									#If member was found . . 
					msg = "S:"+str(msgID)+"::\r\n"
					conn.send(msg.encode("ascii"))							# . . reply with a successful message, completing the handshake
					concat = connectorUsername + connectorIP + connectorPort
					backlinks.append(((connectorInfo[1:4],sdbm_hash(concat)), conn))		#add information of new connection to backlinks array
					global clientStatus
					clientStatus = "CONNECTED"							#Since client now has backlink, it is in CONNECTED state
					_thread.start_new_thread (handlePeer, ("Backward", conn, ))			#Start a new thread to accept messages from peer
					CmdWin.insert(1.0, "\n" + connectorUsername + " has linked to me")
			else:
				conn.close()
		else:
			conn.close()										#anything other than P or T must be failure so close
	
def handlePeer(linkType, conn):
	while conn:												#While the connection is active
		response = conn.recv(1024)									#Receive text messages
		response = str(response.decode("ascii"))
		
		if response:
			if response[0] == 'T':									#T stands for text message, so successful message recvd
				response = response[2:-4]
				msgInfo = response.split(":")
				room = msgInfo[0]								#Get room name of message
			
				if room == myRoom:	
							#if my room, collect all info from message
					originHashID = msgInfo[1]
					originUsername = msgInfo[2]
					originMsgID = msgInfo[3]
					originMsgLen = msgInfo[4]
					originTarget = msgInfo[5]
					originMsg = response[-(int(originMsgLen)):]				#Get the last n chars from response, where n = len of message
					
					lock.acquire()								#acquire the lock since this is the critical section where messages array is modified
					global messages
					if (originHashID, originMsgID) not in messages:				#If message has not been seen before, add it to msg window and store to messages array
						
						messages.append((originHashID, originMsgID))
						lock.release()
						if originTarget:
								
								global username									#Release lock since message has been appended
								if username == originTarget:
									panel.config(image = '')
									encodedimg = cv2.imread("encode.png",cv2.IMREAD_UNCHANGED)
									originMsg = originMsg.split(",")
									originMsg = [ int(x) for x in originMsg ]
									decode = timetodecode(encodedimg,originMsg)
									strng = imagetobinarytochartostring(decode)
									echoMessage(originHashID, originUsername, strng, originMsgID,originTarget)
									MsgWin.insert(1.0, "\n["+originUsername+"] " + strng)
								else:
									global imageFlag
									global flag
									imageFlag = True
									flag = True
									image = Image.open('encode.png')
									image = image.resize((200, 200), Image.ANTIALIAS) #The (250, 250) is (height, width)
									imge = ImageTk.PhotoImage(image)
									panel.config(image = imge)
									echoMessage(originHashID, originUsername, originMsg, originMsgID,originTarget)
									MsgWin.insert(1.0, "\n["+originUsername+"] " + 'sent an image.')
						else:
									panel.config(image = '')
									encodedimg = cv2.imread("encode.png",cv2.IMREAD_UNCHANGED)
									originMsg = originMsg.split(",")
									originMsg = [ int(x) for x in originMsg ]
									decode = timetodecode(encodedimg,originMsg)
									strng = imagetobinarytochartostring(decode)
									echoMessage(originHashID, originUsername, strng, originMsgID,originTarget)
									MsgWin.insert(1.0, "\n["+originUsername+"] " + strng)

											#Echo to all backlinks + forward link
						arr = [member for member in hashes if str(member[1]) == str(originHashID)]
						if not arr:							#If the arr doesnt contain the member that is the origin sender, update members list
							print("Not found hash", str(arr))
							updateMembersList("Peer Handler")
					else:
						print("Recvd repeated message")
						lock.release()							#Release lock, since we have already seen this message so no need to append
						
								


				else:
					print("Recvd message from wrong chat room")
		else:
			break											#Socket broken, look for new forward if forward gone, update backlinks otherwise
	
	if linkType == "Forward":					#If a forward link has been broken, the client is DISCONNECTED, and put back in JOINED state
		updateMembersList("Peer Quit")				#Update members list, reset forward link, look for new P2P peer
		global forwardLink
		forwardLink = ()
		global clientStatus
		clientStatus = "JOINED"
		findP2PPeer(membersList)
	else:								#If back link broken, remove the link from backlinks array
		global backlinks
		for back in backlinks:
			if back[1] == conn:
				backlinks.remove(back)
				break
		
def updateMembersList(*src):
	msg = "J:"+roomname+":"+username+":"+myIP+":"+myPort+"::\r\n"
	try:
		roomServerSocket.send(msg.encode("ascii"))
		response = roomServerSocket.recv(1024)
		response = str(response.decode("ascii"))
		if response:
			if response[0] == 'M':									#M stands for member list, so successful JOIN request
				now = datetime.datetime.now()							#Time info for debugging purposes [to check if KEEPALIVE running every 20 seconds]
				print(src, "Performing JOIN at", now.strftime("%Y-%m-%d %H:%M:%S"))
				response = response[2:-4]
				members = response.split(":")
				global chatHashID
				if chatHashID != members[0]:							#If hashID changed . . 
					global membersList							# . . New members in room, update members list accordingly
					chatHashID = members[0]
					membersList = []
					for group in chunker(members[1:], 3):
						membersList.append(group)
					print("Member list updated!")
					calculateHashes(membersList)						#recalc the hashes
				return True
			elif response[0] == 'F':								#F stands for failure, throw error
				response = response[2:-4]
				CmdWin.insert(1.0, "\nError performing JOIN req: "+response)
				return False
		else:
			return False
	except:
		CmdWin.insert(1.0, "\nConnection to Room Server broken, reconnecting;")
		roomServerSocket.close()	
		_thread.start_new_thread (roomServerConnect, (updateMembersList, ))		#Start a new thread to make a connection with the room server
		
def calculateHashes(membersList):
	global hashes 
	hashes = []
	for member in membersList:
		concat = ""									#concatenate the member info
		for info in member:
			concat = concat + info
		hashes.append((member,sdbm_hash(concat)))					#and add the member info, along with their hash to the hashes array
		if member[0] == username:							
			myInfo = member
	hashes = sorted(hashes, key=lambda tup: tup[1])						#sort the array using the hash ID as the key
	return myInfo

def findP2PPeer(membersList):
	myInfo = calculateHashes(membersList)
	global hashes
	global myHashID
	
	myHashID = sdbm_hash(username+myIP+myPort)									#calc my hash id by concating all info
	start = (hashes.index((myInfo, myHashID)) + 1) % len(hashes)							#find the index to start searching for peer

	while hashes[start][1] != myHashID:										#Loop until you loop back to yourself
		if [item for item in backlinks if item[0] == hashes[start]]:						#if the hashID exists in backlinks array, goto next index		
			start = (start + 1) % len(hashes) 
			continue
		else:
			peerSocket = socket.socket()
			try:												#if not, open a socket and try to connect 
				peerSocket.connect((hashes[start][0][1], int(hashes[start][0][2])))
			except:
				print("Cannot make peer socket connection with ["+hashes[start][0][1]+"], trying another peer")
				start = (start + 1) % len(hashes) 
				continue
			if peerSocket:											#if connection accepted
				if P2PHandshake(peerSocket):								#init P2P handshake
					CmdWin.insert(1.0, "\nConnected via - " + hashes[start][0][0])			#If success, store connection
					global clientStatus
					clientStatus = "CONNECTED"							#Since forward link created, cliennt is now connected
					global forwardLink				
					forwardLink = (hashes[start], peerSocket)					#Store peer info, hashID and the socket to contact peer
					_thread.start_new_thread (handlePeer, ("Forward", peerSocket, ))		#Start a new thread to listen for messages from client
					break
				else:
					peerSocket.close()								#P2P failed, close connection and try again at next index
					start = (start + 1) % len(hashes) 
					continue
			else:
				peerSocket.close()									#Peer rejected connection request, try at next index
				start = (start + 1) % len(hashes) 
				continue		
	if clientStatus != "CONNECTED":
		print("Unable to find forward connection")
		#No need to reschedule, as call to findP2PPeer included in KEEPALIVE procedure, so if client is still in JOINED state after 20 seconds, KEEPALIVE proc will init this procedure. 
	
def P2PHandshake(peerSocket):
	msg = "P:"+roomname+":"+username+":"+myIP+":"+myPort+":"+str(msgID)+"::\r\n"
	try:
		peerSocket.send(msg.encode("ascii")) 
		response = peerSocket.recv(1024)
		response = str(response.decode("ascii"))
		if response:
			if response[0] == 'S':					#If peer responds with S, it is a success, so return True else false
				return True
			else:
				return False
	except:
		return False

def do_Send():
	if userentry.get():
		if clientStatus == "JOINED" or clientStatus == "CONNECTED":		#Only if client is JOINED or CONNECTED do we try and send the message
			global msgID
			msgID += 1
			MsgWin.insert(1.0, "\n["+username+"] "+userentry.get())
			echoMessage(myHashID, username, userentry.get(), msgID,privateUser.get())		#Call echoMessage with my details. 
			print("send")
			print(len(userentry.get()))
		else:
			CmdWin.insert(1.0, "\nNot joined any chat!")
	privateUser.delete(0, END)
	userentry.delete(0, END)	

def echoMessage(originHashID, username, message, msgID, targetUser):
	global flag
	if flag:
		msg = message.split(",")
		msg = [ int(x) for x in msg ]
		print("multiply")
		print(msg[2] * msg[3])
		if msg[2] * msg[3] <= 16:
			img = cv2.imread("Untitled.png")
		elif msg[2] * msg[3] > 16 and msg[2] * msg[3] <= 36:
			img = cv2.imread("green.png")
		else:
			img = cv2.imread("blue.png")
		flag = False
	else:
		if len(message) <= 16:
			img = cv2.imread("Untitled.png")
		elif len(message) > 16 and len(message) <= 36:
			img = cv2.imread("green.png")
		else:
			img = cv2.imread("blue.png")
	img = cv2.cvtColor(img,cv2.COLOR_RGB2RGBA)
	d1 =  stringtochartobinarytoimage(message+chr(3))
	d2 = d1arraytod2array(d1)
	key = timetoencode(img,d2,"encode")
	# encodedimg = cv2.imread("encode.png",cv2.IMREAD_UNCHANGED)
	# decode = timetodecode(encodedimg,key)
	# print(decode)
	# str = imagetobinarytochartostring(decode)
	# print(str)
	key = ','.join(str(v) for v in key)

	msg = "T:"+roomname+":"+str(originHashID)+":"+username+":"+str(msgID)+":"+str(len(key))+":"+str(targetUser)+":"+key+"::\r\n"
	if forwardLink:									#If a forward link exists . . 
		if str(forwardLink[0][1]) != str(originHashID):				# . . and it is not the origin sender
			forwardLink[1].send(msg.encode("ascii"))		#Send message and add to sentTo array
			
	for back in backlinks:								#For all backlinked peers
		if str(back[0][1]) != str(originHashID):				#If they are not the origin sender
			back[1].send(msg.encode("ascii"))			#Send the message and add to the sentTo array
	#CmdWin.insert(1.0, "\nSent to " + str(sentTo))

def do_Quit():
	#Close all sockets - to the room server, to forward link if any, and to all the backlinked clients.
	if roomServerSocket:
		roomServerSocket.close()
		print("Quit: Closed Socket to Room Server")
	if forwardLink:
		forwardLink[1].close()
		print("Quit: Closed Socket to Forward link - ", forwardLink[0][0][0])
	for back in backlinks:
		back[1].close()
		print("Quit: Closed Socket to Backward link - ", back[0][0][0])
	sys.exit(0)

#
# Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)
topscroll = Scrollbar(topframe)
MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red", exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)
topscroll.pack(side=RIGHT, fill=Y, expand=True)
MsgWin.config(yscrollcommand=topscroll.set)
topscroll.config(command=MsgWin.yview)

image = Image.open('encode.png')
image = image.resize((200, 200), Image.ANTIALIAS) #The (250, 250) is (height, width)
imge = ImageTk.PhotoImage(image)
panel = Label(topframe, image = imge)
panel.pack(side = RIGHT, fill=BOTH, expand=True)
# global imageFlag
# if imageFlag:
# 	panel.config(image = img)
# else:
# 	panel.config(image='')
if not imageFlag:
	panel.config(image='')




#Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)
Butt02 = Button(topmidframe, width='8', relief=RAISED, text="List", state=DISABLED, command=do_List)
Butt02.pack(side=LEFT, padx=8, pady=8);
Butt03 = Button(topmidframe, width='8', relief=RAISED, text="Join", state=DISABLED, command=do_Join)
Butt03.pack(side=LEFT, padx=8, pady=8);
Butt04 = Button(topmidframe, width='8', relief=RAISED, text="Send", state=DISABLED, command=do_Send)
Butt04.pack(side=LEFT, padx=8, pady=8);
Butt05 = Button(topmidframe, width='8', relief=RAISED, text="Quit", command=do_Quit)
Butt05.pack(side=LEFT, padx=8, pady=8);

privateUser = Entry(topmidframe, fg="magenta")
privateUser.pack(fill=X, padx=4, pady=4, expand=True)

#Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)
userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)
bottscroll = Scrollbar(bottframe)
CmdWin = Text(bottframe, height='15', padx=5, pady=5, exportselection=0, insertofftime=0)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)
bottscroll.pack(side=RIGHT, fill=Y, expand=True)
CmdWin.config(yscrollcommand=bottscroll.set)
bottscroll.config(command=CmdWin.yview)

def main():
	if len(sys.argv) != 5:
		print("P2PChat.py <server address> <port> <username> <password>")
		sys.exit(2)
	else:
		global roomServerIP
		global roomServerPort
		global myPort
		global users
		global username
		username = sys.argv[3]
		password = sys.argv[4]
		if (username,password) in users.keys():
			myPort = str(users[username,password])
			do_User
			print(myPort)
		else:
			print("Incorrect username or password!")
			sys.exit(2)


		roomServerPort = sys.argv[2]
		roomServerIP = sys.argv[1]
		
		_thread.start_new_thread (roomServerConnect, (do_User, ))		#Start a new thread runnning the server part of P2P
	win.mainloop()
	
def roomServerConnect(callback):	
	global roomServerSocket 
	global roomServerIP
	global roomServerPort
	global myIP
	
	Butt02['state'] = 'disabled'
	Butt03['state'] = 'disabled'
	Butt04['state'] = 'disabled'
	
	#myIP = socket.gethostbyname(socket.gethostname())
	i=0
	while True:
		i = i+1
		print("Trying to connect to Room Server")
		try:
			roomServerSocket = socket.socket()
			roomServerSocket.connect((roomServerIP, int(roomServerPort)))
			myIP = roomServerSocket.getsockname()[0]
			CmdWin.insert(1.0, "\nConnected to Room Server!")
			Butt02['state'] = 'normal'
			Butt03['state'] = 'normal'
			Butt04['state'] = 'normal'
			break		
		except ConnectionRefusedError:
			roomServerSocket.close()
			CmdWin.delete(2.0, 3.0)
			CmdWin.insert(1.0, "\nCannot contact Room Server, will try again in some time (" + str(i) +")")
			time.sleep(5)
	callback()





def d1arraytod2array(array):

    length = len(array)
    sr = length**(0.5)

    if(sr>int(sr)):
        sr  = int(sr)+1
    else:
        sr = int(sr)


    numberofzeropadding = (sr*sr) - length
    paddedarray = paddingzeroesattheend(array, numberofzeropadding)
    new2darray = converter1dto2d(paddedarray, sr)

    return new2darray

def paddingzeroesattheend(array,no):
    i = 0
    while(i<=no):
        array.append([0,0,0,0])
        i=i+1

    return array

def converter1dto2d(array,no):
    new2darray = []
    i =0
    start = 0
    end = no-1
    while(i<no):
        temp = []
        j = start
        while(j<=end):
            temp.append(array[j])
            j=j+1
        new2darray.append(temp)
        start = start+no
        end = end+no
        i=i+1

    return new2darray

def imagetobinarytochartostring(image):
    str = ''
    for pixel in image:
        i = 0
        char =0
        for bits in pixel:
            char = char | bits<<(i*(2))
            i=i+1
        if(char==3):
            break
        str = str + chr(char)

    return str

def timetodecode(image , key):

    hidearray = []
    y  =key[0]
    x  =key[1]
    height_encode_img  = key[2]
    width_encode_img  = key[3]

    height = y
    i = 0
    while (i < height_encode_img):
        width = x
        j = 0
        while (j < width_encode_img):
            pixel  = image[height][width]
            hiddenpixel = []
            indexs = [0, 1, 2, 3]
            for index in indexs:
                hiddenpixel.append(pixel[index]& 0b00000011)

            hidearray.append(hiddenpixel)
            j = j + 1
            width = width + 1

        i = i + 1
        height = height + 1
    return hidearray

def timetoencode(image,message,filename):
    key = []
    hidingarray = message


    if(len(image)>len(hidingarray) and len(image[0])>len(hidingarray[0])):

        y = random.randrange(0, len(image) - len(hidingarray))
        x = random.randrange(0,len(image[0])-len(hidingarray[0]))


        key.append(y)
        key.append(x)
        key.append(len(hidingarray))
        key.append(len(hidingarray[0]))

        height = y
        i = 0
        while(i<len(hidingarray)):
            width = x
            j = 0
            while(j<len(hidingarray[0])):
                pixel = image[height][width]
                hidingpixel  = hidingarray[i][j]
                indexs = [0,1,2,3]
                for index in indexs:
                    last2zero = pixel[index] & 0b11111100
                    pixel[index] = last2zero | hidingpixel[index]
                image[height][width] = pixel
                j = j+1
                width  = width +1

            i=i+1
            height = height+1


    cv2.imwrite(filename+".png", image)

    return key



def stringtochartobinarytoimage(str):

    binaryimg = []
    for letter in str:
        a = ord(letter)
        pixel = []
        i =0
        while(i<4):
            last2 = a & 3
            pixel.append(last2)
            binlast2 = bin(last2)
            a = a>>2
            i=i+1
        binaryimg.append(pixel)

    return binaryimg



if __name__ == "__main__":
	main()
