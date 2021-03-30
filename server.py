import mysql.connector
import socket
from pyope.ope import OPE
import phe


def paillierEncryptedNummber(cipher, expo, pub_key_n):
    
    public_key = phe.PaillierPublicKey(n=int(pub_key_n))
    
    paillier_Chiffre = phe.EncryptedNumber(public_key, int(cipher), int(expo))    
    return paillier_Chiffre


#user£password£database£table£insert£<Name>£<pub_key>£<ciphertextPaillier>£<expoPailier>£<chiffrePYOPE>
def parseur(string):
     
	array = string.split("£")
	print(array)
	user = array[0]
	password = array[1]
	database = array[2]
	table = array[3]

	mydb = mysql.connector.connect(
	host = "localhost",
	user = user,
	password = password,
	database = database)

	mycursor = mydb.cursor()

	print("Connected to database")
	operation = array[4]
	if operation == "insert" and len(array) == 10:
		print("insert")
		name = array[5]
		pub_key = array[6]
		ciphertextPaillier = array[7]
		expoPaillier = array[8]
		chiffrePYOPE = array[9]
		requete = "INSERT INTO "+table+"(name, pub_key, add_number, add_exposant, order_number) VALUES (%s, %s, %s, %s, %s);"
		values = (name, pub_key, ciphertextPaillier, expoPaillier, chiffrePYOPE)
		mycursor.execute(requete, values)
		mydb.commit()
		return "Values inserted"
	elif operation == "select" and len(array) == 6:
		print("select")
		name = array[5]
		requete = "SELECT pub_key, add_number, add_exposant, order_number FROM "+table+" WHERE name LIKE %s %s;"
		values = (name, "")
		mycursor.execute(requete, values)
		string = ""
		for x in mycursor:
			string = name+"£"+str(x[0])+"£"+str(x[1])+"£"+str(x[2])+"£"+str(x[3])
		return string
	elif operation == "compute" and len(array) == 8:
		print("compute")
		name1 = array[5]
		option = array[6]
		name2 = array[7]
		if option == "add":
			requete = "SELECT pub_key, add_number, add_exposant FROM "+table+" WHERE name LIKE %s %s;"
			values = (name1, "")
			mycursor.execute(requete, values)
			pub_key1 = ""
			add_number1 = ""
			add_exposant1 = ""
			for x in mycursor:
				pub_key1 = str(x[0])
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
			
			if pub_key1 != pub_key2:
				return "Error different public key"
			encryptedNumber1 = paillierEncryptedNummber(add_number1, add_exposant1, pub_key1)
			encryptedNumber2 = paillierEncryptedNummber(add_number2, add_exposant2, pub_key2)

			res = encryptedNumber1 + encryptedNumber2

			return name1+"£"+name2+"£"+str(res.ciphertext())+"£"+str(res.exponent)+"£"+str(pub_key1)

		elif option == "order":
			requete = "SELECT order_number FROM "+table+" WHERE name LIKE %s %s;"
			values = (name1, "")
			mycursor.execute(requete, values)
			order_number1 = ""
			for x in mycursor:
				order_number1 = str(x[0])

			requete = "SELECT order_number FROM "+table+" WHERE name LIKE %s %s;"
			values = (name2, "")
			mycursor.execute(requete, values)
			order_number2 = ""
			for x in mycursor:
				order_number2 = str(x[0])

			return name1+"£"+name2+"£"+str(order_number1 > order_number1)

	elif operation == "query" and len(array) == 6:
		print("query")
		requete = array[5]
		mycursor.execute(requete)
		string = ""
		for x in mycursor:
			string += str(x) + "\n"
		return string
	return "Error in the query"
	

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.bind(('', 10050))

socket.listen(5)
client, address = socket.accept()
print("Connected to : ")
print(address)

while True:
	bresponse = client.recv(2048)
	print("\n\n")
	if bresponse is not None:
		print(bresponse.decode("utf-8")+"\n")
		if bresponse.decode("utf-8") == "close":
			break
		else:
			response = parseur(bresponse.decode("utf-8"))
			client.sendall(response.encode("utf-8"))

client.close()
print("Close")
socket.close()