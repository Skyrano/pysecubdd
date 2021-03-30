import mysql.connector
from pyope.ope import OPE
import phe

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="w@VcQ98*a9FZz3",
  database="tp2021_rameau"
)

#public_key, private_key = phe.generate_paillier_keypair()
public_key = phe.PaillierPublicKey(n=int("26727060039838924638921927876128552206541523883976321747215419454074939036284679492917394029313519121262347444703380477917824336276360409816097791841653345883365077405336587142339663089734769095596571875029453808758212035900406960645672820731872626128973412852319591401595709221961056874146332303522365131400821354482054310841320229881187451703111424070228527168426788861229631287308855063694010298442010938785811554771694325436783935300780068374714407707119461772582960965889293196199196424535368207674914545170507488106363969304326192884097693621289367190325240253567255416847659152075567349573225144729754231200023"))
private_key = phe.PaillierPrivateKey(public_key=public_key, p=int("152096033470901325467545180577472979229997713248598296386880267276080730010083403729390369624904734707930937574466585768241117944380535945173132613387888124949620014559055204537799920893900308738167307779906659430150447983277131485257840642388166656472638472944059101078948185621190813434529943206137303552207"), q=int("175724898473123470815825151677578851397593424693436671534299480785421787324194771925979354809300549785241464294977222443067202860910147330723682454660273559505348994851541335851730996939309531211726614439104174058034695134627677409873394646980165095062645532850132147397720343408393080867430836673066949784889"))
keyring = phe.PaillierPrivateKeyring()
keyring.add(private_key)

#print(public_key.n)
#print("mu : "+str(private_key.p)+"\nlambda : "+str(private_key.q))



random_key = b'ZV9+IEpn4GNSX/06RqWUMJU2gwfoBOswlaHlp9Imt+4='
cipher = OPE(random_key)

def evoieDonnee (clair):
    
    paillierChiffre = public_key.encrypt(clair)
    pyopeChiffre = cipher.encrypt(clair)
    
    serialPaillier = (str(paillierChiffre.ciphertext()), paillierChiffre.exponent)
    




chiffre5 = cipher.encrypt(5)
chiffre15 = cipher.encrypt(15)
chiffre20 = cipher.encrypt(32500)

print(str(chiffre5)+" : "+str(chiffre15)+" : "+str(chiffre20))

"""


chiffrePaillier1000 = public_key.encrypt(1000)
chiffrePaillier500 = public_key.encrypt(500)
chiffrePaillier2000 = public_key.encrypt(2000)


#print("Chiffrement : 1000 : "+str(chiffrePaillier1000.ciphertext())+" + exp : "+str(chiffrePaillier1000.exponent)+"; 500 : "+str(chiffrePaillier500.ciphertext())+" + exp : "+str(chiffrePaillier500.exponent)+"; 2000 : "+str(chiffrePaillier2000.ciphertext())+" + exp : "+str(chiffrePaillier2000.exponent)+"\n")
print("Déchiffrement : 1000 : "+str(private_key.decrypt(chiffrePaillier1000))+"; 500 : "+str(private_key.decrypt(chiffrePaillier500))+"; 2000 : "+str(private_key.decrypt(chiffrePaillier2000))+"\n")

chiffrePaillier1000plus500 = chiffrePaillier1000 + chiffrePaillier500
chiffrePaillier1000plus2000 = chiffrePaillier1000 + chiffrePaillier2000

#print("Chiffrement :1500 : "+chiffrePaillier1000plus500+" 3000 : "+chiffrePaillier1000plus2000+"\n")
print("Déhiffrement :1500 : "+str(private_key.decrypt(chiffrePaillier1000plus500))+"; 3000 : "+str(private_key.decrypt(chiffrePaillier1000plus2000))+"\n")

private_key.decrypt(chiffrePaillier1000plus500)


chiffre1000 = cipher.encrypt(1000)
chiffre2000 = cipher.encrypt(2000)
chiffre500 = cipher.encrypt(500)




mycursor = mydb.cursor()

requete = "INSERT INTO numbers(valeur) VALUES ("+str(chiffre1000)+")"
mycursor.execute(requete)
requete = "INSERT INTO numbers(valeur) VALUES ("+str(chiffre2000)+")"
mycursor.execute(requete)
requete = "INSERT INTO numbers(valeur) VALUES ("+str(chiffre500)+")"
mycursor.execute(requete)
mydb.commit()

requete = "SELECT * FROM numbers WHERE (SELECT valeur FROM numbers WHERE id = 1) >= valeur"
#requete = "SELECT * FROM numbers WHERE (SELECT valeur FROM numbers WHERE id = 1) > valeur"
mycursor.execute(requete)

for x in mycursor:
  print(cipher.decrypt(int(x[1])))


requete = "SELECT id,valeur FROM numbers"
mycursor.execute(requete)
for x in mycursor:
  val = int(x[1])
  print(cipher.decrypt(val))
"""