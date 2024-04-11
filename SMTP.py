import socket
import os
import sys
import dns.resolver  # Ensure dnspython is installed
import re
import threading
import shutil

def HELO(args, s, client_address, state):
    fileName = str(client_address[1]) + '.txt'
    if len(args) != 2:
      s.send(b"501 Syntax: HELO hostname \n")
      return
    if state['HELO'] == False:
      with open(fileName, 'w') as the_file:
        the_file.write(" ".join(args) + "\n")
      state['HELO'] = True
      state['file'] = client_address[1]
      state['domain'] = args[1]
      s.send(b"250 "+ str(client_address[1]).encode() + b" OK \n")
    else:
      open(fileName, 'w').close()
      with open(fileName, 'a') as the_file:
        the_file.write(" ".join(args) + "\n")
      state['HELO'] = False
      state['MAIL'] = False
      state['RCPT'] = False
      state['completedTransaction'] = False
      state['HELO'] = True
      s.send(b"250 "+ str(client_address[1]).encode() + b" OK \n")

def MAIL(args, s, client_address, state):
    fileName = str(state['file']) + '.txt'
    if state['HELO'] == False:
      s.send(b"503 5.5.1 Error: send HELO/EHLO first \n")
    else:
      if state['MAIL'] == False:
        if len(args) != 2:
          s.send(b"501 5.5.4 Syntax: MAIL FROM:<address> \n")
          return
        checkSyntax = re.match(r"(^FROM:<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>$)", args[1], re.IGNORECASE)
        if(checkSyntax):
          if state['data'] == False:
            with open(fileName, 'a') as the_file:
              the_file.write(" ".join(args) + "\n")
            state['MAIL'] = True
            s.send(b"250 2.1.0 Ok \n")
          else:
              state['file'] = state['file'] + 1
              fileName = str(state['file']) + '.txt'
              with open(fileName, 'a') as the_file:
                the_file.write("helo " + state['domain'] + "\n")
                the_file.write(" ".join(args) + "\n")
              state['MAIL'] = True
              state['completedTransaction'] = False
              s.send(b"250 2.1.0 Ok \n")
        else:
          s.send(b"501 5.1.7 Bad sender address syntax \n")
      else:
        s.send(b"503 5.5.1 Error: nested MAIL command \n")
    
def RCPT(args, s, client_address, state):
  print(client_address)	
  if state['MAIL'] == True and state['HELO'] == True:
    if len(args) != 2:
      s.send(b"501 5.5.4 Syntax: RCPT TO:<address> \n")
      return
    checkSyntax = re.match(r"(^TO:<[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+>$)", args[1], re.IGNORECASE)
    if(checkSyntax):
      state['recipient'] = checkSyntax.group()
      fileName = str(state['file']) + '.txt'
      with open(fileName, 'a') as the_file:
        the_file.write(" ".join(args) + "\n")
      state['RCPT'] = True
      s.send(b"250 2.1.5 Ok \n")
    else:
      s.send(b"501 5.1.3 Bad recipient address syntax \n")
  else:
    s.send(b"503 5.5.1 Error: need MAIL command \n")

def DATA(args, s, client_address, state):
  fileName = str(state['file']) + '.txt'
  if state['MAIL'] == True and state['HELO'] == True and state['RCPT'] == True:
    s.send(b"354 End data with <CR><LF>.<CR><LF> \n")
    data = receiveData(s, state)
    with open(fileName, 'a') as the_file:
      the_file.write("data \n")
      the_file.write(data.decode())
      the_file.write("\nquit \n")
    state['MAIL'] = False
    state['RCPT'] = False
    s.send(b"250 queued " + str(state['file']).encode() + b" \n")
    state['data'] = True
    state['completedTransaction'] = True
    threading.Thread(target=relayData, args=(state['file'], state)).start()
  elif state['MAIL'] == True and state['HELO'] == True and state['RCPT'] == False:
    s.send(b"503 5.5.1 Error: need RCPT command \n")
  else:
    s.send(b"503 5.5.1 Error: bad sequence of commands \n")


def NOOP(args, s, client_address, state):
  s.send("250 Ok \n")

def QUIT(args, s, client_address, state):
  state['loop'] = False
  s.send("221 2.0.0 Bye \n")
  s.close()
  if state['completedTransaction'] == False:
    fileName = str(state['file']) + '.txt'
    os.remove(fileName)


#To avoid pishing and brute force discovery of emails this function is not implemented
def VRFY(args, s, client_address, state):
  if len(args) != 2:
    s.send("501 5.5.4 Syntax: VRFY address \n")
    return
  checkSyntax = re.match("TO:<\w+@\w+\.\w+>", args[1], re.IGNORECASE)
  if(checkSyntax):
    s.send("252  Cannot VRFY user \n")
  else:
    s.send("450 4.1.2 Recipient address rejected: Domain not found \n")
  

def RSET(args, s, client_address, state):
  fileName = str(state['file'] + '.txt')
  with open(fileName) as f:
    first_line = f.readline()
  open(fileName, 'w').close()
  with open(fileName, 'a') as the_file:
    the_file.write(first_line)
  state['MAIL'] = False
  state['RCPT'] = False
  s.send("250 OK \n")


def findMXServer(email):
    domain = re.search("@[\w.]+", email)
    if domain:
        domain = domain.group()
        domain = domain[1:]
        try:
            mailExchangeServers = dns.resolver.resolve(domain, 'MX')
        except Exception as e:
            print("No domain found:", e)
            return None
        lowestPref = ""
        pref = mailExchangeServers[0].preference
        for rdata in mailExchangeServers:
            if rdata.preference <= pref:
                lowestPref = rdata.exchange.to_text()
        lowestPref = lowestPref[:-1]
	print(lowestPref)
        return lowestPref
    return None


import socket

def relayData(client_address, state):
    filename = str(client_address) + '.txt'
    HOST = findMXServer(state['recipient'])
    if HOST:
        PORT = 25
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(100)  # Set a timeout for the connection attempt (adjust as needed)
                s.connect((HOST, PORT))
                s.settimeout(None)  # Reset the timeout after successful connection
                data = s.recv(1024)
                print('Received', repr(data.decode()))
                with open(filename, 'r') as fp:
                    for line in fp:
                        line = line.rstrip() + "\r\n"
                        print('Sent', repr(line))
                        s.sendall(line.encode())
                        if line == ".\r\n":
                            data = s.recv(1024)
                            print('Received', repr(data.decode()))
                            answer = data.decode().split(" ")
                            if answer[0] != "250":
                                raise Exception("Error: Unexpected response from server")
                os.remove(filename)  # Remove the file after successful relay
        except socket.timeout as e:
            print("Connection timed out:", e)
            # Handle the timeout error gracefully (e.g., retry or log the error)
            # Copy the file to the errors directory for further inspection
            src_path = os.path.realpath(filename)
            dst_folder = os.path.join('errors', os.path.basename(src_path))
            os.makedirs(os.path.dirname(dst_folder), exist_ok=True)  # Ensure the errors directory exists
            shutil.copy(src_path, dst_folder)
        except Exception as e:
            print("Error occurred during relay:", e)
            # Handle other types of exceptions as needed
            # Copy the file to the errors directory for further inspection
            src_path = os.path.realpath(filename)
            dst_folder = os.path.join('errors', os.path.basename(src_path))
            os.makedirs(os.path.dirname(dst_folder), exist_ok=True)  # Ensure the errors directory exists
            shutil.copy(src_path, dst_folder)
    else:
        print("No mail exchange server found for recipient:", state['recipient'])
        # Copy the file to the errors directory for further inspection
        src_path = os.path.realpath(filename)
        dst_folder = os.path.join('errors', os.path.basename(src_path))
        os.makedirs(os.path.dirname(dst_folder), exist_ok=True)  # Ensure the errors directory exists
        shutil.copy(src_path, dst_folder)



#end the loop of handling a client and delete the commands file
def closeAndClean(s, state):
  state['loop'] = False
  s.close()
  if state['completedTransaction'] == False:
    fileName = str(state['file']) + '.txt'
    os.remove(fileName)

#keep on recieving data until you find a dot on a new line
def receiveData(s, state):
    bufferSize = 4096
    buffer = s.recv(bufferSize)
    # Remove timeout if commands are received
    buffering = True
    while buffering:
        if b"\r\n.\r\n" in buffer:
            return buffer
        else:
            more = s.recv(4096)
            if not more:
                buffering = False
            else:
                buffer += more
    return buffer

dispatch = {
    'helo': HELO,
    'mail': MAIL,
    'rcpt': RCPT,
    'data': DATA,
    'quit': QUIT,
    'vrfy': VRFY,
    'rest': RSET,
    'noop': NOOP
}

#processes all the commands recieved from the SMTP client
def process_network_command(command, args, s, client_address, state):
  command = command.lower()
  try:
    dispatch[command](args, s, client_address, state)
  except KeyError:
    s.send("502 5.5.2 Error: command not recognized \n")

#recieve a line
def linesplit(s, state):
  try:
    #add timeout to the connection if no commands are recieved
    s.settimeout(300)
    buffer = s.recv(4096)
    print(buffer)
    #remove timeout if commands are recieved
    s.settimeout(None)
    buffering = True
    while buffering:
      #prevent empty lines from being processed
      if buffer == "\r\n":
        s.send("500 5.5.2 Error: bad syntax \n")
      if b"\n" in buffer:
          (line, buffer) = buffer.decode('utf-8').split("\n", 1)
          return line
      else:
          more = s.recv(4096)
          if not more:
              buffering = False
          else:
              buffer += more
  except socket.timeout:
    closeAndClean(s, state)
  

#take care of the sessions of one client with all of it's transactions
#each call to this function is handled in a seperate section
def handleClient(s, client_address):
    state = {
        'HELO': False,
        'MAIL': False,
        'RCPT': False,
        'loop': True,
        'data': False,
        'recipient': "",
        'file': 0,
        'domain': "",
        'completedTransaction': False
    }
    try:
        s.send("220 SMTP USER 1.0 \n".encode('utf-8'))  # Modified line
        print('connection from', client_address, file=sys.stderr)
        # Receive the data in small chunks
        while state['loop']:
            lines = linesplit(s, state)
            args = lines.split()
            # prevent empty lines from invoking the function
            if len(args) > 0:
                process_network_command(args[0], args, s, client_address, state)
    finally:
        # Clean up the connection
        s.close()


def main():
    print(sys.argv)
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Prevent "address is already in use" error
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the port
    server_address = (sys.argv[1], 25)
    print('starting up on %s port %s' % server_address, file=sys.stderr)
    sock.bind(server_address)
    # Listen for incoming connections
    sock.listen(0)

    while True:
        # Wait for a connection
        print('waiting for a connection', file=sys.stderr)
        connection, client_address = sock.accept()
        if connection:
            threading.Thread(target=handleClient, args=(connection, client_address)).start()

if __name__ == "__main__":
    main()

