import requests 
import hashlib 
import sys
import time
from tkinter import *

#initializing tk with master root
root = Tk()
caption = root.title('Password Checker')
root.configure(bg='white')


#sends info to main
def send_info():
	info = Password.get()
	main(info)


Label(root, bg='white', text='Password Checker', pady=10, fg='LightGreen', font=('Comic Sans MS', 20, 'underline')).grid(row=0, column=0, columnspan=2)

Password = Entry(root, bg='white', width=50, borderwidth=10, font=('Comic Sans MS', 10))
Password.insert(0,'Enter you password: ')
Password.grid(row=1, column=0, columnspan=2, padx=10)

button = Button(root, bg='white', text='Enter', command=send_info, font=('Comic Sans MS', 10))
button.grid(column=0, row=2, columnspan=2, pady=10)


#requests info from api
def request_api_password(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check the api and try again')
	return res 


#finds the count of leaks 
def get_password_leaks_count(hashes, hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_to_check:
			return count
	return 0


#finds password using hashing and kananmimity
def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_password(first5_char)
	return get_password_leaks_count(response, tail)


#main returns info
def main(password):
	count = pwned_api_check(password)
	if count:
		response = f'"{password}", WAS FOUND {count} TIMES, YOU SHOULD CHANGE YOUR PASSWORD.'
		label = Label(root, bg='white', fg='red', text=response, font=('Comic Sans MS', 12), padx=10, pady=10)
		label.grid(row=3, column=0, columnspan=2)
	else:
		response = f'"{password}", WAS NEVER BREACHED.'
		label = Label(root, bg='white', fg='green', text=response, font=('Comic Sans MS', 12), padx=10, pady=10)
		label.grid(row=3, column=0, columnspan=2)

root.mainloop()