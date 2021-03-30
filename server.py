import mysql.connector
import socket
from pyope.ope import OPE
import phe


#Cette fonction permet de recréer un objet "EncryptedNumber" à partir des éléments de sérialisation, à savoir le cipherText, exponent et la clef publique ayant servit à chiffrer le nombre clair
def paillierEncryptedNumber(cipher, expo, pub_key_n):
    public_key = phe.PaillierPublicKey(n=int(pub_key_n))
    paillier_Chiffre = phe.EncryptedNumber(public_key, int(cipher), int(expo))    
    return paillier_Chiffre


#Cette fonctione est la fonction principales du server : on parse un string en entrée et on fait des requête à la base de données en fonction de ce qui est demandé, avant de rendre un résultat sous la formed'un string
def parseur(string):
     
	array = string.split("£") #notre séparateur est "£"
	user = array[0]
	password = array[1]
	database = array[2]
	table = array[3]

	#on se connecte à la base de données avec les credentials donnés
	mydb = mysql.connector.connect(
	host = "localhost",
	user = user,
	password = password,
	database = database)

	mycursor = mydb.cursor()
	print("Connected to database")
	
	operation = array[4] #on check quelle est l'opération voulue et on effecute celle-ci
	if operation == "insert" and len(array) == 10: #la vérification de la taille permet de vérifier qu'il n'y ait au moins pas d'erreur dans le nombre d'arguments
		name = array[5]  							#l'insert en lui même est assez classique, mais les données qui transitent sont ici chiffrées par le client et ainsi elle ne sont jamais connues du serveur, qui va ensuite pouvoir les utiliser quand même comme on le verra
		pub_key = array[6]
		ciphertextPaillier = array[7]
		expoPaillier = array[8]
		chiffrePYOPE = array[9]
		requete = "INSERT INTO "+table+"(name, pub_key, add_number, add_exposant, order_number) VALUES (%s, %s, %s, %s, %s);"
		values = (name, pub_key, ciphertextPaillier, expoPaillier, chiffrePYOPE)
		mycursor.execute(requete, values)
		mydb.commit()
		return "Values inserted"
	elif operation == "select" and len(array) == 6: #on renvoie les données d'un nom
		name = array[5]
		requete = "SELECT pub_key, add_number, add_exposant, order_number FROM "+table+" WHERE name LIKE %s %s;"
		values = (name, "")
		mycursor.execute(requete, values)
		string = ""
		for x in mycursor:
			string = name+"£"+str(x[0])+"£"+str(x[1])+"£"+str(x[2])+"£"+str(x[3])
		return string
	elif operation == "compute" and len(array) == 8: #on fait une opération sur les valeurs
		name1 = array[5]
		option = array[6]
		name2 = array[7]
		if option == "add": #on additionne les valeurs
			requete = "SELECT pub_key, add_number, add_exposant FROM "+table+" WHERE name LIKE %s %s;"
			values = (name1, "")
			mycursor.execute(requete, values)
			pub_key1 = ""
			add_number1 = ""
			add_exposant1 = ""
			for x in mycursor: 
				pub_key1 = str(x[0]) #on récupère la clé publique car elle est requise pour additionner
				add_number1 = str(x[1])
				add_exposant1 = str(x[2])

			requete = "SELECT pub_key, add_number, add_exposant FROM "+table+" WHERE name LIKE %s %s;"
			values = (name2, "")
			mycursor.execute(requete, values)
			pub_key2 = ""
			add_number2 = ""
			add_exposant2 = ""
			for x in mycursor:
				pub_key2 = str(x[0])
				add_number2 = str(x[1])
				add_exposant2 = str(x[2])
			
			if pub_key1 != pub_key2: #si les clés ne sont pas les mêmes (nombres chiffrés avec la même clé privée) on ne peut pas additionner les nombres
				return "Error different public key"
			encryptedNumber1 = paillierEncryptedNumber(add_number1, add_exposant1, pub_key1) #on recréé un nombre utilisable à partir des données de la base qui ont été séparées en 2 nombres
			encryptedNumber2 = paillierEncryptedNumber(add_number2, add_exposant2, pub_key2) #/!\ on ne déchiffre pas ici les nombres (on a de toutes façons que la clé publique de disponible), on recréé simplement des nombres additionnables sous la bonne forme en combinant les informations stockées

			res = encryptedNumber1 + encryptedNumber2 #on peut alors calculer le résultat de manière simple, nombre donc le déchiffrement donne le résultat correct
			return name1+"£"+name2+"£"+str(res.ciphertext())+"£"+str(res.exponent)+"£"+str(pub_key1)

		elif option == "order": #on compare les valeurs
			requete = "SELECT order_number FROM "+table+" WHERE name LIKE %s %s;"
			values = (name1, "")
			mycursor.execute(requete, values)
			order_number1 = ""
			for x in mycursor: #ici on ne récupère pas de clé publique, cependant les 2 nombres doivent aussi étre chiffrés avec la même clé (symétrique pour ce chiffrement ci)
				order_number1 = str(x[0])

			requete = "SELECT order_number FROM "+table+" WHERE name LIKE %s %s;"
			values = (name2, "")
			mycursor.execute(requete, values)
			order_number2 = ""
			for x in mycursor:
				order_number2 = str(x[0])

			return name1+"£"+name2+"£"+str(order_number1 > order_number2) #on peut comparer les valeurs naturellement avec ">" grâce au chiffrement utilisé préservant l'ordre
	elif operation == "query" and len(array) == 6: #permet de faire une requête libre dont le résultat est concaténé dans un string et renvoyé au client
		requete = array[5]
		mycursor.execute(requete)
		string = ""
		for x in mycursor:
			string += str(x) + "\n"
		return string
	elif operation == "delete" and len(array) == 6: #permet de supprimer des lignes de la BDD, utile dans le cas de nos tests
		name = array[5]
		requete = "DELETE FROM "+table+" WHERE name LIKE %s %s;"
		values = (name, "")
		mycursor.execute(requete, values)
		mydb.commit()
		return name+" deleted"
	return "Error in the query"
	

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('', 10050)) #port arbitraire

socket.listen(5) 
client, address = socket.accept() #on lance le serveur en écoute sur le port
print("Connected to : ")
print(address)

while True:
	bresponse = client.recv(2048)
	if bresponse is not None:
		print(bresponse.decode("utf-8")+"\n") #on print la réponse pour debug côté serveur
		if bresponse.decode("utf-8") == "close":
			break
		else:
			response = parseur(bresponse.decode("utf-8")) #on parse la requête et on effectue les opérations nécessaires
			client.sendall(response.encode("utf-8")) #on renvoie la réponse au client

client.close()
print("Close")
socket.close()