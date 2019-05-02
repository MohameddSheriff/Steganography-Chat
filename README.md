# Environment needed
Linux to run the room server.
Python 3.*

# Frameworks needed
OpenCV
PIL
Tkinter

#Starting the application
1- Open a terminal in the project's directory

2- run the following command: 
	./room_server_64 <port_number>
ex: ./room_server_64 3000

3- open as many terminal instances as the number of users you would like to run concurrently

4- for each terminal run the following command: python P2P-chat.py <server_ip> <port_number> <username> <password>
where <server_ip> is the ip of the hosting machine,
<port_number> is the number used in step 2

for the <username> and <password>, here is a list of predefined users inside the code,
'ramy','1234': which uses port 8000
'fox','12345': which uses port 8001
'sherif','123': which uses port 8002
'hany','12': which uses port 8003.


#Using the application
5- after logging in, you would find a text box just under the buttons, we proceed by writing a room name and then clicking "join"
if a room with this name already exists, you will directly join this room, if not, a new room with this name is created and you will join it immediately.

6- after joining the room using as many users as you want. Now is the time to chat, type a message in the same text box used in step 5, and then click "send", the message is broadcasted to every user in the room.

7- if you want to send a secret message to one user inside the room, just add their username in the textbox beside the buttons, then write your message normally like you did in step 6.
The mentioned user will get the original message, while other users inside the room only receive a picture where the message is encoded.
