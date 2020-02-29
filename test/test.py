import sys
from giltzarrapo import Giltzarrapo
from printer import cprint, ecprint
from datetime import datetime as dt

passph = '123'
passwd = 'abc'
num_process = 3
sb = None

if '-e' in sys.argv:
	#RSA KEYS
	cprint('Generando claves...', color = 'cyan', end = '\r')
	s = dt.now()
	Giltzarrapo.generateRSApair(passphrase = passph)
	e = dt.now()
	ecprint(['Generacion de claves ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')


	#ENCRYPT
	g = Giltzarrapo(n_processes = num_process)
	#read
	cprint('Leyendo fichero...', color = 'cyan', end = '\r')
	s = dt.now()
	g.readPlain('testfile.txt')
	e = dt.now()
	ecprint(['Lectura de fichero   ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')
	#encrypt
	cprint('Cifrando fichero...', color = 'cyan', end = '\r')
	s = dt.now()
	g.encrypt(passwd, 'giltza_rsa.pub', fast = False, selected_block = sb)
	e = dt.now()
	ecprint(['Cifrado de fichero   ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')
	#save
	cprint('Escribiendo fichero...', color = 'cyan', end = '\r')
	s = dt.now()
	g.save('testfile.enc')
	e = dt.now()
	ecprint(['Escritura de fichero ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')


#DECRYPT
#g = Giltzarrapo(n_processes = num_process)
g = Giltzarrapo()
#read
cprint('Leyendo fichero...', color = 'cyan', end = '\r')
s = dt.now()
g.readEncrypted('testfile.enc')
e = dt.now()
ecprint(['Lectura de fichero   ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')
#decrypt
cprint('Descifrando fichero...', color = 'cyan', end = '\r')
s = dt.now()
g.decrypt(passwd, 'giltza_rsa', passph, selected_block = sb)
e = dt.now()
ecprint(['Descifrado de fichero', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')
#save
cprint('Escribiendo fichero...', color = 'cyan', end = '\r')
s = dt.now()
g.save('testfile.dec')
e = dt.now()
ecprint(['Escritura de fichero ', str(e - s)], color = ['cyan', 'yellow'], template = '{} : {}')
