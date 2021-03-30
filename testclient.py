import socket

hote = "localhost"
port = 10050

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((hote, port))
print("Connection on "+ str(port))

request = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£" #c'est ca qui est envoyé, donc à voir la syntaxe de ce qu'on envoie (séparation des termes avec £?)

socket.send(request.encode("utf-8"))

bresponse = socket.recv(1024)
if bresponse is not None:
	response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select
	print(response)

print("Close")
socket.close()