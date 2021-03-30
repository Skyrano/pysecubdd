import socket
import mysql.connector
from pyope.ope import OPE
import phe

#Chaine de charactère permettant la génération de la clef public de Paillier (asymétrique) afin de garder une persitence au sein de l'application.
#Pour une mise en service, il nous faudrait réfléchir à un loader de couple clef publique/privé pour le chiffrement de Paillier
pub_key_n = "26727060039838924638921927876128552206541523883976321747215419454074939036284679492917394029313519121262347444703380477917824336276360409816097791841653345883365077405336587142339663089734769095596571875029453808758212035900406960645672820731872626128973412852319591401595709221961056874146332303522365131400821354482054310841320229881187451703111424070228527168426788861229631287308855063694010298442010938785811554771694325436783935300780068374714407707119461772582960965889293196199196424535368207674914545170507488106363969304326192884097693621289367190325240253567255416847659152075567349573225144729754231200023"
#De même, nous avons 2 chaînes permettant de générer la clef privée du chiffrement de Paillier
priv_key_p = "152096033470901325467545180577472979229997713248598296386880267276080730010083403729390369624904734707930937574466585768241117944380535945173132613387888124949620014559055204537799920893900308738167307779906659430150447983277131485257840642388166656472638472944059101078948185621190813434529943206137303552207"
priv_key_q = "175724898473123470815825151677578851397593424693436671534299480785421787324194771925979354809300549785241464294977222443067202860910147330723682454660273559505348994851541335851730996939309531211726614439104174058034695134627677409873394646980165095062645532850132147397720343408393080867430836673066949784889"

#Nous recréons l'objet clef publique et clef privée de la librairie phe à partir des chaîne 
public_key = phe.PaillierPublicKey(n=int(pub_key_n))
private_key = phe.PaillierPrivateKey(public_key=public_key, p=int(priv_key_p), q=int(priv_key_q))

#Nous initialisons un porte clef, car même si cela n'est pas utile dans notre POC, il sera nécessaire de gérer un trousseau si nouvenions à déployer notre middleware
keyring = phe.PaillierPrivateKeyring()
keyring.add(private_key)

#Nous générons la clef et le chiffreur du chifrement OPE (symétrique)
random_key = b'ZV9+IEpn4GNSX/06RqWUMJU2gwfoBOswlaHlp9Imt+4='
cipher = OPE(random_key)

#Cette fonction permet de généré un string encapsulant les information d'un nombre chiffré par OPE et Paillier
def envoieDonnee (clair):
    
  paillierChiffre = public_key.encrypt(clair)
  pyopeChiffre = cipher.encrypt(clair)
  
  requeteEnvoieDonnee = pub_key_n+"£"+str(paillierChiffre.ciphertext())+"£"+str(paillierChiffre.exponent)+"£"+str(pyopeChiffre)
  
  return requeteEnvoieDonnee

#Cette fonction permet de déchiffrer les informations rendu par la base de donnée à la suite d'un select
def receptionSelect (paillierCipher, paillierExpo, pyopeChiffre, pub_key_recep_n):
  
  #Nous recréons la clef publique  
  pub_key_recep = phe.PaillierPublicKey(n=int(pub_key_recep_n))
  #Nous recréons le nombre chiffré
  paillierChiffre = phe.EncryptedNumber(pub_key_recep, int(paillierCipher), int(paillierExpo))
  
  #Nous déchiffrons Paillier
  clairePaillier = keyring.decrypt(paillierChiffre)
  
  #Nous déchiffrons OPE
  clairePyope = cipher.decrypt(int(pyopeChiffre))
  
  if(clairePaillier != clairePyope):
    return (False, 0)
  else:
    return (True, clairePaillier)
  
  
#Cette fonction permet d'envoyer une requète select au server, puis de parser et interpréter la réponse du server
def selectQuery (select):
  socket.sendall(select.encode("utf-8"))
  
  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select

  if response == "Error in the query":
    print("Error in the query")
  else:
    array = response.split("£")

    reception = receptionSelect(array[2], array[3], array[4], array[1])
    if reception[0]:
      print("Nous avons bien reussi à récupérer la valeur sotockée par "+array[0]+" : "+str(reception[1])+"\n")
    else:
      print("Il y a eu une erreur lors de la récupération de la valeur stockée par "+array[0]+"\n")
  
  
#Cette fonction permet de déchiffrer les informations rendu par la base de donnée à la suite d'un add
def receptionAddition (paillierCipher, paillierExpo, pub_key_recep_n):
  
  pub_key_recep = phe.PaillierPublicKey(n=int(pub_key_recep_n))

  paillierChiffre = phe.EncryptedNumber(pub_key_recep, int(paillierCipher), int(paillierExpo))
  
  clairePaillier = keyring.decrypt(paillierChiffre)
  
  return clairePaillier


#Cette fonction permet d'envoyer une requète add au server, puis de parser et interpréter la réponse du server
def addQuery(add):
  socket.sendall(add.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") 

  if response == "Error in the query":
    print("Error in the query"+"\n")
  elif response == "Error different public key":
    print("Error Different public key"+"\n")
  else:
    array = response.split("£")
  
    reception = receptionAddition(array[2], array[3], array[4])
    print("Le résultat de l'addition faite par le serveur entre les valeurs de "+array[0]+" et "+array[1]+" donnent : "+str(reception)+"\n")

#Cette fonction permet d'envoyer une requète order au server, puis de parser et interpréter la réponse du server  
def orderQuery(order):
  socket.sendall(order.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8")

  if response == "Error in the query":
    print("Error in the query"+"\n")
  else:
    array = response.split("£")

    print("La valeur de "+array[0]+" est plus grande que la valeur de "+array[1]+" : "+array[2]+"\n")

#Cette fonction permet d'envoyer une requète query au server  
def standardQuery(query):
  socket.sendall(query.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8")

  print("Reponse query : \n"+response+"\n")

#Cette fonction permet d'envoyer une requète insert au server
def insertQuery(insert):
  socket.sendall(insert.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8")
  
  print("Reponse insert : "+response+"\n")

#Cette fonction permet d'envoyer une requète delet au server
def deleteQuery(delete):
  socket.sendall(delete.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8")
  
  print("Reponse delete : "+response+"\n")


#Voici la structure des requêtes au serveur, afin que celui-ci puisse parser les informations :
#user£password£database£table£insert£<Name>£<pub_key>£<ciphertextPaillier>£<expoPailier>£<chiffrePYOPE>
#user£password£database£table£select£<Name>
#user£password£database£table£compute£<Name>£add|order£<Name>
#user£password£database£table£query£<requeteComplete>
#user£password£database£table£delete£<Name>

#Création de 3 requètes d'insertion
insert1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Xavier£"+envoieDonnee(5) 
insert2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Nathalie£"+envoieDonnee(15)
insert3 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Bob£"+envoieDonnee(20)

#Création de 1 requète de selection
select1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£select£Xavier"

#Création de 2 requètes d'addidtion
add1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Xavier£add£Bob" #Ajoute le chiffré de Xavier au chiffré de bob, puis renvoie le résultat
add2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Nathalie£add£Bob"

#Création de 2 requètes d'order
order1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Nathalie£order£Bob" #Compare les chiffrés de Nathalie et Bob et renvoie le résultat
order2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Bob£order£Nathalie"

#Création de 1 requête query standard
#Selectionne les noms des lignes qui on un nombre clair plus grand ou égal à celui de Nathalie
#Nous pouvons par exemple dire que nous voulons toutes les personnes ayant plus ou autant d'argent sur leur compte que Nathalie, sans savoir combien précisémment ils ont sur leur compte
specialQuery1 = "SELECT name FROM users WHERE order_number >= ((SELECT order_number FROM users WHERE name = 'Nathalie') LIMIT 1)"
query1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£query£"+specialQuery1

#Création de 3 requètes de delete
delete1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£delete£Xavier"
delete2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£delete£Nathalie"
delete3 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£delete£Bob"


hote = "localhost"
port = 10050

#Connexion au server
socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((hote, port))
print("Connection on "+ str(port))

#Envoie des données
insertQuery(insert1)
insertQuery(insert2)
insertQuery(insert3)

selectQuery(select1)

addQuery(add1)
addQuery(add2)

orderQuery(order1)
orderQuery(order2)

standardQuery(query1)

deleteQuery(delete1)
deleteQuery(delete2)
deleteQuery(delete3)

#Fin de la connexion
endServer = "close"
socket.sendall(endServer.encode("utf-8"))

print("Close")
socket.close()