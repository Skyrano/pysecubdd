import socket
import mysql.connector
from pyope.ope import OPE
import phe

pub_key_n = "26727060039838924638921927876128552206541523883976321747215419454074939036284679492917394029313519121262347444703380477917824336276360409816097791841653345883365077405336587142339663089734769095596571875029453808758212035900406960645672820731872626128973412852319591401595709221961056874146332303522365131400821354482054310841320229881187451703111424070228527168426788861229631287308855063694010298442010938785811554771694325436783935300780068374714407707119461772582960965889293196199196424535368207674914545170507488106363969304326192884097693621289367190325240253567255416847659152075567349573225144729754231200023"
priv_key_p = "152096033470901325467545180577472979229997713248598296386880267276080730010083403729390369624904734707930937574466585768241117944380535945173132613387888124949620014559055204537799920893900308738167307779906659430150447983277131485257840642388166656472638472944059101078948185621190813434529943206137303552207"
priv_key_q = "175724898473123470815825151677578851397593424693436671534299480785421787324194771925979354809300549785241464294977222443067202860910147330723682454660273559505348994851541335851730996939309531211726614439104174058034695134627677409873394646980165095062645532850132147397720343408393080867430836673066949784889"

public_key = phe.PaillierPublicKey(n=int(pub_key_n))
private_key = phe.PaillierPrivateKey(public_key=public_key, p=int(priv_key_p), q=int(priv_key_q))

keyring = phe.PaillierPrivateKeyring()
keyring.add(private_key)

random_key = b'ZV9+IEpn4GNSX/06RqWUMJU2gwfoBOswlaHlp9Imt+4='
cipher = OPE(random_key)

def envoieDonnee (clair):
    
  paillierChiffre = public_key.encrypt(clair)
  pyopeChiffre = cipher.encrypt(clair)
  
  requeteEnvoieDonnee = pub_key_n+"£"+str(paillierChiffre.ciphertext())+"£"+str(paillierChiffre.exponent)+"£"+str(pyopeChiffre)
  
  return requeteEnvoieDonnee

def receptionSelect (paillierCipher, paillierExpo, pyopeChiffre, pub_key_recep_n):
      
  pub_key_recep = phe.PaillierPublicKey(n=int(pub_key_recep_n))
  paillierChiffre = phe.EncryptedNumber(pub_key_recep, int(paillierCipher), int(paillierExpo))
  
  clairePaillier = keyring.decrypt(paillierChiffre)
  
  clairePyope = cipher.decrypt(int(pyopeChiffre))
  
  if(clairePaillier != clairePyope):
    return (False, 0)
  else:
    return (True, clairePaillier)
  
  
  
def selectQuery (select):
  socket.sendall(select.encode("utf-8"))
  
  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select

  print("Reponse select : \n"+response+"\n")
  if response == "Error in the query":
    print("Error in the query")
  else:
    array = response.split("£")

    reception = receptionSelect(array[2], array[3], array[4], array[1])
    if reception[0]:
      print("Nous avons bien reussi à récupérer la valeur sotockée par "+array[0]+" : "+str(reception[1])+"\n")
    else:
      print("Il y a eu une erreur lors de la récupération de la valeur stockée par "+array[0]+"\n")
  

def receptionAddition (paillierCipher, paillierExpo, pub_key_recep_n):
  
  pub_key_recep = phe.PaillierPublicKey(n=int(pub_key_recep_n))

  paillierChiffre = phe.EncryptedNumber(pub_key_recep, int(paillierCipher), int(paillierExpo))
  
  clairePaillier = keyring.decrypt(paillierChiffre)
  
  return clairePaillier


def addQuery(add):
  socket.sendall(add.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select

  print("Reponse add : \n"+response+"\n")
  if response == "Error in the query":
    print("Error in the query"+"\n")
  elif response == "Error different public key":
    print("Error Different public key"+"\n")
  else:
    array = response.split("£")
  
    reception = receptionAddition(array[2], array[3], array[4])
    print("Le résultat de l'addition faite par le serveur entre les valeurs de "+array[0]+" et "+array[1]+" donnent : "+str(reception)+"\n")
  
def orderQuery(order):
  socket.sendall(order1.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select

  print("Reponse order : \n"+response+"\n")

  if response == "Error in the query":
    print("Error in the query"+"\n")
  else:
    array = response.split("£")

    print("La valeur de "+array[0]+" est plus grande que la valeur de "+array[1]+" : "+array[2]+"\n")

def standardQuery(query):
  socket.sendall(query.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select

  print("Reponse query : \n"+response+"\n")

def insertQuery(insert):
  socket.sendall(insert.encode("utf-8"))

  bresponse = socket.recv(2048)
  if bresponse is not None:
    response = bresponse.decode("utf-8") # la réponse du serveur, un nombre j'imagine si on part sur du select
  
  print("Reponse insert : "+response+"\n")


#user£password£database£table£insert£<Name>£<pub_key>£<ciphertextPaillier>£<expoPailier>£<chiffrePYOPE>
#user£password£database£table£select£<Name>
#user£password£database£table£compute£<Name>£add|order£<Name>
#user£password£database£table£query£<requeteTotale>

insert1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Xavier£"+envoieDonnee(5) 
insert2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Nathalie£"+envoieDonnee(15)
insert3 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Bob£"+envoieDonnee(20)

select1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£select£Xavier"

add1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Xavier£add£Bob" #ajoute le chiffré de Xavier au chiffré de bob, puis renvoie le résultat
add2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Nathalie£add£Bob"

order1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Nathalie£order£Bob" #Compare les chiffrés de Nathalie et Bob et renvoie le résultat
order2 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£compute£Bob£order£Nathalie"

specialQuery1 = "SELECT name FROM users WHERE order_number => (SELECT order_number FROM users WHERE name = 'Nathalie')"
query1 = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£query£"+specialQuery1


hote = "localhost"
port = 10050

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((hote, port))
print("Connection on "+ str(port))

#request = "root£w@VcQ98*a9FZz3£tp2021_rameau£users£insert£Xavier£789£416486£4" #c'est ca qui est envoyé, donc à voir la syntaxe de ce qu'on envoie (séparation des termes avec £?)

insertQuery(insert1)
insertQuery(insert2)
insertQuery(insert3)


selectQuery(select1)

addQuery(add1)
addQuery(add2)

orderQuery(order1)
orderQuery(order2)

standardQuery(query1)

endServer = "close"
socket.sendall(endServer.encode("utf-8"))

print("Close")
socket.close()