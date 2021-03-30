import mysql.connector

mydb = mysql.connector.connect(
	host = "localhost",
	user = "root",
	password = "w@VcQ98*a9FZz3",
	database = "tp2021_rameau")

mycursor = mydb.cursor()
print("connected")
table = "users"

name1 = "unnomsuper"
name2 = "David"

requete = "SELECT add_number, add_exposant FROM "+table+" WHERE name LIKE %s %s;"
values = (name1, "")
mycursor.execute(requete, values)
add_number1 = ""
add_exposant1 = ""
for x in mycursor:
	add_number1 = str(x[0])
	add_exposant1 = str(x[1])

requete = "SELECT add_number, add_exposant FROM "+table+" WHERE name LIKE %s %s;"
values = (name2, "")
mycursor.execute(requete, values)
add_number2 = ""
add_exposant2 = ""
for x in mycursor:
	add_number2 = str(x[0])
	add_exposant2 = str(x[1])

print(add_number1)
print(add_exposant1)
print(add_number2)
print(add_exposant2)




